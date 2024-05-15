from pytz import timezone
from flask import Flask, render_template
from flask_compress import Compress
from snowflake.snowpark import Session
from snowflake.snowpark.functions import udf, col
import os
try:
    from config import *
except ModuleNotFoundError:
    print('Deploying in prod environment.')

app = Flask(__name__) 
Compress(app)


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
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

    # SQL query to select all columns from the leaderboard view
    df = session.table('GOLF_LEAGUE.ANALYTICS.LEADERBOARD_DISPLAY_DETAILED_VW').select("RANK","ENTRY_NAME","TOURNAMENT","TEAM_SCORE","SELECTIONS").order_by('RANK')
    results = df.collect()
    # Query to get the name of the active tournament
    tournament_name = results[0]['TOURNAMENT'] if results else None
    
    # Get the latest timestamp from the leaderboard
    last_updated = session.table('GOLF_LEAGUE.ANALYTICS.LIVE_TOURNAMENT_STATS_FACT').select('LAST_UPDATED','EVENT_NAME').filter(col('EVENT_NAME') == tournament_name).order_by('LAST_UPDATED', ascending=False).limit(1).collect()[0]['LAST_UPDATED']
    last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
    session.close()

    # Start HTML response, using the tournament name
    return render_template('leaderboard.html', tournament_name=tournament_name, results=results, last_updated=last_updated)