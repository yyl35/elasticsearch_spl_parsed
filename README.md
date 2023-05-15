# **Simply convert SPL (Splunk Processing Language) similar to Splunk into DSL (Domain-specific Language)**

Using **soc/spl_to_es.py** Directly If you don't want to run the Django
project,  
you can directly use the spl_to_es.py file. To do this, modify the
parsed_query variable assignment on line 380: parsed_query =
parse_query(spl_query3) Replace spl_query3 with your own SPL query
string. Then, run the spl_to_es.py script using Python: python
spl_to_es.py The script will output the converted Elasticsearch DSL
query.


# **Installation and Setup**

Install Django and other required packages using the requirements.txt
file by running the following command:

<pre>
pip install -r requirements.txt
</pre>
Navigate to the Django project directory (where the manage.py file is
located), and run the following command to start the development server:

<pre>
python manage.py runserver
</pre>
Open a web browser and visit
http://127.0.0.1:8000/ to access the Django application.


# **Usage Example**

<pre>
index=indexA | stats count(field1) by field2 | where field = "abc" or
field3 = "efg" | eval field4="123"+field2+"abc" | table field1 field2

index=filebeat-* | exists bytes | timechart sum(bytes) by clientip |
where sum > 1000 | eval cnt=sum * 100 | table @timestamp clientip cnt
</pre>

# **Available functions:**
**index  
stats  
timechart  
eval  
split  
exists  
table  
where**


# **Explanation of each function:**

**index:** Specifies the index or indexes to search in ES. It filters the
data based on the specified index(es).

**stats:** Performs statistical operations on the search results. It allows
you to calculate various statistics such as count, sum, avg, etc.,
on specific fields.

**timechart:** Generates a time-based chart or table from the search
results. It helps in visualizing and analyzing data over time by
aggregating the results based on a time interval.

**eval:** Evaluates an expression and creates a new field or modifies
existing fields based on the evaluated expression. It is used for
performing calculations, manipulating string values, and creating
derived fields.

**split:** Splits a JSON field's key into strings.

**exists:** Filter the field where exists in document

**table:** Displays the specified fields in tabular format. It allows you to
choose and arrange the fields to be displayed in the output.

**where:** Filters the search results based on specified conditions. It
helps in narrowing down the results by applying logical conditions on
fields, such as equality, inequality, or pattern matching.

```

```

