import re
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import pandas as pd
import json
OPERATIONS_MAPPING = {
    "count": "value_count",
    "sum": "sum",
    "avg": "avg",
    "min": "min",
    "max": "max"
}

def parse_query(query):
    parts = re.split(r'\s*\|\s*', query)
    funcs = []
    for part in parts:
        if part.startswith('index='):
            index_name = part[6:]
            if '*' in index_name:
                index_name = index_name.replace('*', '')
                funcs.append(('index', [f"{index_name}*"]))
            else:
                funcs.append(('index', [index_name]))
        elif part.startswith('stats '):
            stat_args = part[6:].split(' by ')
            agg_field = stat_args[0]
            group_by = stat_args[1] if len(stat_args) > 1 else ''
            funcs.append(('stats', [agg_field, group_by]))
        elif part.startswith('timechart '):
            timechart_args = part[10:].split(' ')
            timechart_interval = timechart_args[0].split('=')[1]
            timechart_field = timechart_args[1]
            if 'by' in timechart_args:
                group_by_index = timechart_args.index('by')
                group_by_field = timechart_args[group_by_index + 1]
            else:
                group_by_field = ''
            funcs.append(('timechart', [timechart_interval, timechart_field, group_by_field]))
        elif part.startswith('where '):
            where_conditions = part[len('where '):]
            and_conditions = where_conditions.split(' and ')
            conditions = [cond.split(' or ') for cond in and_conditions]
            funcs.append(('where', conditions))
        elif part.startswith('table '):
            table_fields = part[6:].split(' ')
            funcs.append(('table', table_fields))
        elif part.startswith('split '):
            split_args = part[6:].strip().split(',')
            funcs.append(('split', [split_args]))
        elif part.startswith('eval '):
            eval_args = part[5:].split(',')
            funcs.append(('eval', eval_args))
        elif part.startswith('exists '):
            exists_fields = part[7:].split(',')
            funcs.append(('exists', exists_fields))

        else:
            raise ValueError(f"Invalid query syntax: {part}")
    return funcs


def build_dsl_query(parsed_query, start_time=None, end_time=None):
    dsl_query = {
        "size": 1000,
        "query": {"bool": {"filter": []}},
        "aggs": {}
    }
    aggregation_fields = []
    aggregation_fields_t = []
    timechart_group_by = []
    index_name = None
    group_by_fields = []
    timechart_agg = []
    timechart_group_by_fields = []
    if start_time and end_time:
        dsl_query["query"]["bool"]["filter"].append({"range": {"@timestamp": {"gte": start_time, "lte": end_time}}})
    for func, args in parsed_query:
        if func == "index":
            index_name = args[0]
        elif func == "stats":
            agg_field, group_by = args
            group_by_fields = group_by.split(',')
            nested_aggs = dsl_query["aggs"]
            for field in group_by_fields:
                nested_aggs[field] = {"terms": {"field": field, "size": 1000}, "aggs": {}}
                nested_aggs = nested_aggs[field]["aggs"]
            operation, field = re.match(r'(\w+)\(([\w\.]+)\)', agg_field).groups()
            op = OPERATIONS_MAPPING[operation]
            nested_aggs[operation] = {op: {"field": field}}
            if operation not in aggregation_fields:
                aggregation_fields.append(operation)
            is_numeric = True

        elif func == "timechart":
            timechart_interval, timechart_agg, *timechart_group_by = args
            timechart_group_by = [x for x in (timechart_group_by[0].split(',') if timechart_group_by else []) if x]
            operation, field = re.match(r'(\w+)\(([\w\.]+)\)', timechart_agg).groups()
            op = OPERATIONS_MAPPING[operation]
            dsl_query["aggs"]["date_histogram"] = {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": timechart_interval
                },
                "aggs": {}
            }
            print("timechart_group_by:", timechart_group_by)
            if timechart_group_by:
                print("yes")
                nested_aggs = dsl_query["aggs"]["date_histogram"]["aggs"]
                for group_by_field in timechart_group_by:
                    nested_aggs[group_by_field] = {"terms": {"field": group_by_field, "size": 1000}, "aggs": {}}
                    nested_aggs = nested_aggs[group_by_field]["aggs"]
                nested_aggs["timechart"] = {op: {"field": field}}
            else:
                dsl_query["aggs"]["date_histogram"]["aggs"]["timechart"] = {op: {"field": field}}

            if operation not in aggregation_fields:
                aggregation_fields_t.append(operation)
            is_numeric = True


        elif func == "where":
            operators = [">=", "<=", "!=", ">", "<","==","="]
            and_conditions = args
            global_filter = []
            for or_conditions in and_conditions:
                or_filter = []
                for condition in or_conditions:
                    operator = None
                    for op in operators:
                        if op in condition:
                            operator = op
                            break
                    if not operator:
                        raise ValueError(f"Invalid where syntax: {condition}")
                    field, value = condition.split(operator, 1)
                    field = field.strip()
                    value = value.replace('"', '').strip()
                    if field in aggregation_fields:
                        if is_numeric:
                            filter = {
                                "bucket_selector": {
                                    "buckets_path": {field: field},
                                    "script": f"params.{field} {operator} {value}"
                                }
                            }
                            nested_aggs[field + "_filter"] = filter
                        else:
                            raise ValueError("Non-numeric conditions on aggregation fields are not supported.")
                    elif field in aggregation_fields_t:
                        if is_numeric:
                            filter = {
                                "bucket_selector": {
                                    "buckets_path": {field: "timechart"},
                                    "script": f"params.{field} {operator} {value}"
                                }
                            }
                            nested_aggs["value" + "_filter"] = filter
                        else:
                            raise ValueError("Non-numeric conditions on aggregation fields are not supported.")
                    else:
                        if operator == "=":
                            filter = {"term": {field: value}}
                        elif operator == "!=":
                            filter = {"bool": {"must_not": {"term": {field: value}}}}
                        elif operator in (">", "<", ">=", "<="):
                            range_op = {">": "gt", "<": "lt", ">=": "gte", "<=": "lte"}[operator]
                            filter = {"range": {field: {range_op: value}}}
                        else:
                            raise ValueError(f"Unsupported operator: {operator}")
                        or_filter.append(filter)
                if len(or_filter) > 1:
                    global_filter.append({"bool": {"should": or_filter, "minimum_should_match": 1}})
                else:
                    global_filter.extend(or_filter)
            dsl_query["query"]["bool"]["filter"].extend(global_filter)

        elif func == "exists":
                  exists_fields = args
                  for field in exists_fields:
                      dsl_query["query"]["bool"]["filter"].append({"exists": {"field": field}})

        elif func == "table":
            pass
        elif func == "split":
            pass
        elif func == "eval":
            pass
        else:
            raise ValueError(f"Unknown function: {func}")
    dsl_params = {
        'timechart_group_by': timechart_group_by,  # 添加这一行
    }

    return index_name, dsl_query, timechart_group_by,timechart_agg


def get_nested_value(data, keys):
    if keys and data:
        key = keys.pop(0)
        if key in data:
            return get_nested_value(data[key], keys)
    return data

def process_response(response, timechart_group_by,parsed_query):  # 添加timechart_group_by参数

    def parse_nested_buckets(buckets, group_by, current_row=None):
        rows = []
        if current_row is None:
            current_row = {}

        for bucket in buckets:
            row = current_row.copy()
            row[group_by[0]] = bucket['key_as_string'] if 'key_as_string' in bucket else bucket['key']

            if len(group_by) > 1:
                nested_group_by = group_by[1:]
                if nested_group_by[0] in bucket:
                    if 'buckets' in bucket[nested_group_by[0]]:
                        nested_buckets = bucket[nested_group_by[0]]['buckets']
                        rows += parse_nested_buckets(nested_buckets, nested_group_by, row)
                    else:
                        row.update({nested_group_by[0]: bucket[nested_group_by[0]]['value']})
                        rows.append(row)
                else:
                    row.update(bucket)
                    rows.append(row)
            else:
                for key, value in bucket.items():
                    if key not in group_by:
                        row.update({key: value['value'] if isinstance(value, dict) else value})
                rows.append(row)
        return rows

    # 获取聚合结果
    if 'aggregations' in response:
        aggregations = response['aggregations']
        # 检查查询是否包含timechart
        is_timechart = any(func == "timechart" for func, _ in parsed_query)

        if is_timechart:
            # 使用timechart的处理方式
            data=[]
            if timechart_group_by:
                for date_bucket in response["aggregations"]["date_histogram"]["buckets"]:
                    timestamp = date_bucket["key_as_string"]
                    for nested_bucket in date_bucket[timechart_group_by[0]]["buckets"]:
                        row = {"_time": timestamp}
                        for group_by_field in timechart_group_by:
                            row[group_by_field] = nested_bucket["key"]
                            row["timechart"] = nested_bucket["timechart"]["value"]
                        data.append(row)
            else:
                for date_bucket in response["aggregations"]["date_histogram"]["buckets"]:
                    timestamp = date_bucket["key_as_string"]
                    row = {"_time": timestamp}
                    row["timechart"] = date_bucket["timechart"]["value"]
                    data.append(row)
            df = pd.DataFrame(data)
        else:
            # 使用stats的处理方式
            stats_group_by_fields = [args for func, args in parsed_query if func == "stats"]
            if stats_group_by_fields:
                stats_group_by_fields = stats_group_by_fields[0][1].split(',')
            else:
                stats_group_by_fields = []
            if stats_group_by_fields:
                first_group_by_field = stats_group_by_fields[0]
                while 'buckets' not in aggregations[first_group_by_field]:
                    first_group_by_field = list(aggregations.keys())[0]
                    aggregations = aggregations[first_group_by_field]
                try:
                    table_args = [args for func, args in parsed_query if func == "table"][0]
                except IndexError:
                    table_args = None

                data = parse_nested_buckets(aggregations[first_group_by_field]['buckets'], stats_group_by_fields)
                df = pd.DataFrame(data)
                if table_args:
                    df = df[table_args]
            else:
                df = pd.DataFrame()
    else:
        # 如果响应中没有聚合，则从 response['hits']['hits'] 创建数据框
        df = pd.DataFrame([hit['_source'] for hit in response['hits']['hits']])
        # 获取 table 函数的参数

    def process_expression(row, expression_parts, strings):
        result = ''
        for part in expression_parts:
            part = part.strip()
            if part in [f'strings[{idx}]' for idx in range(len(strings))]:
                result += strings[int(part[8:-1])]
            else:
                result += str(pd.eval(part, engine="python", local_dict=row.to_dict()))
        return result

    for func, args in parsed_query:
        if func == 'eval':
            eval_expressions = args

            # 检查 DataFrame 行数
            if len(df) <= 10000:
                for eval_expression in eval_expressions:
                    # 执行 eval 表达式
                    column_name, expression = eval_expression.split('=', 1)

                    # 使用正则表达式识别字符串
                    string_pattern = re.compile(r'"(.*?)"')
                    strings = string_pattern.findall(expression)

                    # 替换字符串
                    for idx, s in enumerate(strings):
                        expression = expression.replace(f'"{s}"', f'strings[{idx}]')

                    # 在 DataFrame 上执行替换后的表达式
                    if len(strings) > 0 and '+' in expression:
                        column_name, expression = column_name.strip(), expression.strip()
                        expression_parts = expression.split("+")
                        df[column_name] = df.apply(lambda row: process_expression(row, expression_parts, strings),
                                                   axis=1)
                    else:
                        df[column_name.strip()] = df.apply(
                            lambda row: pd.eval(expression, engine="python", local_dict=row.to_dict()), axis=1)
            else:
                print("提示：请先执行聚合操作。")

    table_args = [args for func, args in parsed_query if func == "table"]
    if table_args:
        # 如果存在 table 函数参数，则过滤数据框的列
        table_args = table_args[0]
        df = df[table_args]
    split_args = [args for func, args in parsed_query if func == "split"]
    if split_args:
        fields_to_split = split_args[0][0]
        columns_to_remove = []
        for keys in fields_to_split:
            key_parts = keys.split('.')
            column = key_parts.pop(0)
            columns_to_remove.append(column)
            values = []
            for idx, row in df.iterrows():
                values.append(get_nested_value(row[column], key_parts.copy()))
            df[f'{keys}'] = values

        # 移除原始列
        for column in columns_to_remove:
            if column in df.columns:
                df = df.drop(column, axis=1)
    return df

def spl_to_es_query(spl_query, start_time=None, end_time=None):
    # 将之前的代码放在这个函数中
    parsed_query = parse_query(spl_query)
    if start_time is None or end_time is None:
        start_time = datetime.utcnow() - timedelta(days=3)
        end_time = datetime.utcnow()

    index_name, dsl_query = build_dsl_query(parsed_query, start_time=start_time, end_time=end_time)
    print(dsl_query)
    response = es.search(index=index_name, body=dsl_query)
    # 处理响应并返回 DataFrame
    df = process_response(response, timechart_group_by,parsed_query)  # 传递timechart_group_by参数

    return dsl_query, df


if __name__ == "__main__":

    es = Elasticsearch(
        ['https://192.168.10.205:9200'],
        http_auth=('elastic', 'elastic'),
        verify_certs=False,
        min_delay_between_sniffing=60,
    )
    spl_query = 'index=filebeat-* |stats sum(bytes) by @timestamp,clientip|where sum>200000|table @timestamp clientip sum'
    spl_query2 = 'index=filebeat-* |timechart span=15m count(bytes)|where value<200'
    spl_query3 = 'index=filebeat-* |where method="POST"|where status !=404'
    parsed_query = parse_query(spl_query3)
    start_time = datetime.utcnow() - timedelta(days=3)
    end_time = datetime.utcnow()
    index_name, dsl_query ,timechart_group_by,timechart_agg = build_dsl_query(parsed_query, start_time=start_time, end_time=end_time)
    response = es.search(index=index_name, body=dsl_query)
    # 处理响应并打印 DataFrame
    df = process_response(response,timechart_group_by, parsed_query)
    print(df)












