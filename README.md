Simply convert SPL (Splunk Processing Language) similar to Splunk into DSL (Domain-specific Language)

Using soc/spl_to_es.py Directly
If you don't want to run the Django project, you can directly use the spl_to_es.py file. To do this, modify the parsed_query variable assignment on line 380:

parsed_query = parse_query(spl_query3)
Replace spl_query3 with your own SPL query string. Then, run the spl_to_es.py script using Python:

python spl_to_es.py
The script will output the converted Elasticsearch DSL query.

Install Django and other required packages using the requirements.txt file by running the following command:

pip install -r requirements.txt
Navigate to the Django project directory (where the manage.py file is located), and run the following command to start the development server:


python manage.py runserver
Open a web browser and visit http://127.0.0.1:8000/ to access the Django application.

