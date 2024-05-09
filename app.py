from flask import Flask, render_template
from snowflake.snowpark import Session
from snowflake.snowpark.functions import udf
import os
try:
    from config import *
except ModuleNotFoundError:
    print('Deploying in prod environment.')

app = Flask(__name__) 

def create_snowpark_session():
    if os.getenv('SNOWFLAKE_ACCOUNT') == None:
        connection_parameters = {
            "account": SNOWFLAKE_ACCOUNT,
            "user": SNOWFLAKE_USER,
            "password": SNOWFLAKE_PASSWORD,
            "role": SNOWFLAKE_ROLE,
            "warehouse": SNOWFLAKE_WAREHOUSE,
            "database": SNOWFLAKE_DATABASE,
            "schema": SNOWFLAKE_SCHEMA
        }

    else:
         connection_parameters = {
            "account": os.getenv("SNOWFLAKE_ACCOUNT"),
            "user": os.getenv("SNOWFLAKE_USER"),
            "password": os.getenv("SNOWFLAKE_PASSWORD"),
            "role": os.getenv("SNOWFLAKE_ROLE"),
            "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
            "database": os.getenv("SNOWFLAKE_DATABASE"),
            "schema": os.getenv("SNOWFLAKE_SCHEMA")
        }
    session = Session.builder.configs(connection_parameters).create()
    return session

@app.route("/")
def leaderboard():
    session = create_snowpark_session()

    # SQL query to select all columns from the leaderboard view
    df = session.table('GOLF_LEAGUE.ANALYTICS.LEADERBOARD_DISPLAY_DETAILED_VW').select("RANK","ENTRY_NAME","TOURNAMENT","TEAM_SCORE","SELECTIONS").order_by('RANK')
    results = df.collect()
    
    session.close()

    # Query to get the name of the active tournament
    tournament_name = results[0]['TOURNAMENT'] if results else None

    # Start HTML response, using the tournament name
    return render_template('leaderboard.html', tournament_name=tournament_name, results=results)

# if __name__ == "__main__":
#     app.run(debug=True)
