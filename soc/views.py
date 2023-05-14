from django.shortcuts import render
from .spl_to_es import spl_to_es_query # 导入您提供的后端代码
from elasticsearch import Elasticsearch
from . import spl_to_es
from dateutil.parser import parse

es = Elasticsearch(
    ['https://192.168.10.205:9200'],
    http_auth=('elastic', 'elastic'),
    verify_certs=False,
    min_delay_between_sniffing=60,
)

def search(request):
    if request.method == 'POST':
        spl_query = request.POST.get('spl_query')
        start_time_str = request.POST.get('start_time')
        end_time_str = request.POST.get('end_time')


        # 将 start_time 和 end_time 从字符串转换为 datetime 对象
        start_time = parse(start_time_str)
        end_time = parse(end_time_str)

        # 调用 spl_to_es 中的函数
        parsed_query = spl_to_es.parse_query(spl_query)
        print(parsed_query)
        index_name, dsl_query ,timechart_group_by,timechart_agg= spl_to_es.build_dsl_query(parsed_query, start_time=start_time, end_time=end_time)
        print(dsl_query)
        response = es.search(index=index_name, body=dsl_query)


        df = spl_to_es.process_response(response,timechart_group_by, parsed_query)

        result = {
            'dsl_query': dsl_query,
            'dataframe': df.to_html(classes='table table-striped table-hover', justify='left',float_format='%.2f')

        }
        return render(request, 'results.html', result)
    else:
        return render(request, 'search.html')





