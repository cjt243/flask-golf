from pytz import timezone
from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
from flask_compress import Compress
from snowflake.snowpark import Session
from snowflake.snowpark.functions import col
import os
import base64
try:
    from config import *
except ModuleNotFoundError:
    print('Deploying in prod environment.')

app = Flask(__name__) 
Compress(app)


def create_snowpark_session():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    # Get private key and connection parameters from either environment variables or config
    private_key = os.getenv("SNOWFLAKE_PRIVATE_KEY") or SNOWFLAKE_PRIVATE_KEY
    account = os.getenv("SNOWFLAKE_ACCOUNT") or SNOWFLAKE_ACCOUNT
    user = os.getenv("SNOWFLAKE_USER") or SNOWFLAKE_USER
    role = os.getenv("SNOWFLAKE_ROLE") or SNOWFLAKE_ROLE
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE") or SNOWFLAKE_WAREHOUSE
    database = os.getenv("SNOWFLAKE_DATABASE") or SNOWFLAKE_DATABASE
    schema = os.getenv("SNOWFLAKE_SCHEMA") or SNOWFLAKE_SCHEMA

    # Decode and format the private key
    key_bytes = base64.b64decode(private_key)
    p_key = serialization.load_pem_private_key(
        key_bytes,
        password=None,  # None since key is not encrypted
        backend=default_backend()
    )
    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Create connection parameters
    connection_parameters = {
        "account": account,
        "user": user,
        "private_key": pkb,
        "role": role,
        "warehouse": warehouse,
        "database": database,
        "schema": schema,
        "authenticator": "SNOWFLAKE_JWT"
    }

    session = Session.builder.configs(connection_parameters).create()
    return session

@app.route("/")
def leaderboard():
    session = create_snowpark_session()
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

    # SQL query to select all columns from the leaderboard view
    df = session.table('GOLF_LEAGUE.APPLICATION.LEADERBOARD_DISPLAY_DETAILED_VW').select("RANK","ENTRY_NAME","TOURNAMENT","TEAM_SCORE","PICKS").order_by('RANK')
    results = df.collect()
    # Query to get the name of the active tournament
    # tournament_name = results[0]['TOURNAMENT'] if results else None
    tournament_name = 'Masters Tournament'
    
    # Get the latest timestamp from the leaderboard
    last_updated = session.table('GOLF_LEAGUE.APPLICATION.LATEST_LEADERBOARD_UPDATE_VW').select('LATEST_UPDATE','TOURNAMENT_NAME').filter(col('TOURNAMENT_NAME') == tournament_name).limit(1).collect()[0]['LATEST_UPDATE']
    last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
    session.close()

    # Start HTML response, using the tournament name
    return render_template('leaderboard.html', tournament_name='Masters Tournament', results=results, last_updated=last_updated)

# @app.route("/players")
# def player_standings():
#     session = create_snowpark_session()
#     session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

#     # SQL query to select all columns from the player leaderboard view
#     df = session.table('GOLF_LEAGUE.ANALYTICS.PLAYER_LEADERBOARD_DETAILED_VW').select(
#         "EVENT_NAME", "POSITION", "THRU", "FULL_NAME", "ROUND", "CUT_TOTAL", "TOTAL", 
#         "SG_OTT", "SG_APP", "SG_PUTT", "SG_T2G", "SG_ARG", "SG_TOTAL", "ENTRY_NAMES", "SELECTIONS"
#     ).order_by('TOTAL').fillna(0)
#     results = df.collect()

    
#     # Query to get the name of the active tournament
#     tournament_name = results[0]['EVENT_NAME'] if results else None
    
#     # Get the latest timestamp from the leaderboard
#     last_updated = session.table('GOLF_LEAGUE.ANALYTICS.LIVE_TOURNAMENT_STATS_FACT').select('LAST_UPDATED','EVENT_NAME').filter(col('EVENT_NAME') == tournament_name).order_by('LAST_UPDATED', ascending=False).limit(1).collect()[0]['LAST_UPDATED']
#     last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
#     session.close()

#     # Start HTML response, using the tournament name
#     return render_template('player_standings.html', tournament_name=tournament_name, results=results, last_updated=last_updated)

# @app.route("/make_picks")
# def make_picks():
#     session = create_snowpark_session()
#     session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")
#     tournament = session.table('GOLF_LEAGUE.ANALYTICS.TOURNAMENTS').filter(col('ACTIVE_TOURNAMENT') == True).collect()[0]['EVENT']


#     pick_options_df = session.table('GOLF_LEAGUE.ANALYTICS.PICK_OPTIONS').to_pandas()
#     pick_list = pick_options_df["player_name"].to_list()
#     pick_list = [x.split(', ')[1]+' '+x.split(', ')[0] for x in pick_list]

#     # create slicers to separate out the pick lists
#     first = pick_list[0:5]
#     second = pick_list[5:16]
#     third = pick_list[16:]

#     session.close()

#     return render_template('pick_form.html', tournament_name=tournament, first=first, second=second, third=third)

# @app.route("/submit_picks", methods=["POST"])
# def submit_picks():
#     entry_name = request.form.get("entry_name")
#     golfer_1 = request.form.get("golfer_1")
#     golfer_2_and_3 = request.form.getlist("golfer_2_and_3")
#     golfer_4_and_5 = request.form.getlist("golfer_4_and_5")

#     if len(golfer_2_and_3) == 2 and len(golfer_4_and_5) == 2 and entry_name:
#         golfer_2, golfer_3 = golfer_2_and_3
#         golfer_4, golfer_5 = golfer_4_and_5
  
#         session = create_snowpark_session()
#         session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")
#         tournament = session.table('GOLF_LEAGUE.ANALYTICS.TOURNAMENTS').filter(col('ACTIVE_TOURNAMENT') == True).collect()[0]['EVENT']

#         try:
#             session.write_pandas(
#                 pd.DataFrame.from_dict(
#                     {
#                         "ENTRY_NAME": [entry_name],
#                         "GOLFER_1": [golfer_1],
#                         "GOLFER_2": [golfer_2],
#                         "GOLFER_3": [golfer_3],
#                         "GOLFER_4": [golfer_4],
#                         "GOLFER_5": [golfer_5],
#                         "TOURNAMENT": [tournament]
#                     }
#                 ),
#                 table_name='POOL_STAGING', database='GOLF_LEAGUE', schema='ANALYTICS', overwrite=False
#             )
#             session.close()
#             return render_template('submit_success.html', tournament=tournament,entry_name=entry_name, golfers=[golfer_1, golfer_2, golfer_3, golfer_4, golfer_5]), 200
#         except Exception as e:
#             session.close()
#             return f"An error occurred: {e}", 500
#     else:
#         return "Validation Check Failed - please make sure you have 5 golfers selected and a valid entry name.", 400

if __name__ == "__main__":
    app.run(debug=True)