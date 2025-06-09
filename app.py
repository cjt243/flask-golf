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

    # Get authentication details and connection parameters from either environment variables or config
    private_key = os.getenv("SNOWFLAKE_PRIVATE_KEY") or SNOWFLAKE_PRIVATE_KEY
    password = os.getenv("SNOWFLAKE_PASSWORD") or globals().get("SNOWFLAKE_PASSWORD")
    account = os.getenv("SNOWFLAKE_ACCOUNT") or SNOWFLAKE_ACCOUNT
    user = os.getenv("SNOWFLAKE_USER") or SNOWFLAKE_USER
    role = os.getenv("SNOWFLAKE_ROLE") or SNOWFLAKE_ROLE
    warehouse = os.getenv("SNOWFLAKE_WAREHOUSE") or SNOWFLAKE_WAREHOUSE
    database = os.getenv("SNOWFLAKE_DATABASE") or SNOWFLAKE_DATABASE
    schema = os.getenv("SNOWFLAKE_SCHEMA") or SNOWFLAKE_SCHEMA

    if private_key:
        # Decode and format the private key for key-pair authentication
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
    elif password:
        # Fallback to password-based authentication (useful for local testing)
        connection_parameters = {
            "account": account,
            "user": user,
            "password": password,
            "role": role,
            "warehouse": warehouse,
            "database": database,
            "schema": schema
        }
    else:
        raise ValueError("Snowflake credentials not provided")

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
    tournament_name = 'PGA Championship'
    
    # Debug: Check if Patrick Cantlay is in any picks
    for result in results:
        if 'Patrick Cantlay' in result['PICKS']:
            print(f"DEBUG: Found Patrick Cantlay in {result['ENTRY_NAME']} picks: {result['PICKS']}")
            break
    
    # Get the cut line value and player scores to determine missed cuts
    cut_line = None
    player_scores = {}
    try:
        player_df = session.table('GOLF_LEAGUE.APPLICATION.PLAYER_FOCUSED_LEADERBOARD_VW').select('GOLFER', 'CUT_LINE', 'TOTAL_SCORE_INTEGER', 'PLAYER_STATUS', 'TOURNAMENT').filter(col('TOURNAMENT') == tournament_name)
        player_results = player_df.collect()
        cut_line = player_results[0]['CUT_LINE'] if player_results else None
        
        # Create a dictionary of player scores and cut status
        for player in player_results:
            golfer_name = player['GOLFER']
            player_scores[golfer_name] = {
                'score': player['TOTAL_SCORE_INTEGER'],
                'status': player['PLAYER_STATUS']
            }
            
            # Also create entries for names with numbers (e.g., "Patrick Cantlay 2")
            # Check common number suffixes that might appear in picks
            for suffix in [' 1', ' 2', ' 3', ' 4', ' 5']:
                numbered_name = golfer_name + suffix
                player_scores[numbered_name] = {
                    'score': player['TOTAL_SCORE_INTEGER'],
                    'status': player['PLAYER_STATUS']
                }
        
        # Debug: Print some player data to see what we're getting
        print(f"DEBUG: Cut line: {cut_line}")
        print(f"DEBUG: Found {len(player_scores)} players")
        if 'Patrick Cantlay' in player_scores:
            print(f"DEBUG: Patrick Cantlay status: {player_scores['Patrick Cantlay']['status']}")
        else:
            # Check for similar names
            cantlay_matches = [name for name in player_scores.keys() if 'cantlay' in name.lower()]
            print(f"DEBUG: Cantlay name matches: {cantlay_matches}")
            if cantlay_matches:
                print(f"DEBUG: {cantlay_matches[0]} status: {player_scores[cantlay_matches[0]]['status']}")
        
        # Debug: Print all players with "cut" status
        cut_players = [name for name, data in player_scores.items() if data['status'] and 'cut' in data['status'].lower()]
        print(f"DEBUG: Players with cut status: {cut_players}")
    except:
        cut_line = None
        player_scores = {}
    
    # Get the latest timestamp from the leaderboard
    last_updated = session.table('GOLF_LEAGUE.APPLICATION.LATEST_LEADERBOARD_UPDATE_VW').select('LATEST_UPDATE','TOURNAMENT_NAME').filter(col('TOURNAMENT_NAME') == tournament_name).limit(1).collect()[0]['LATEST_UPDATE']
    last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
    session.close()

    # Start HTML response, using the tournament name
    return render_template('leaderboard.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line, player_scores=player_scores)

@app.route("/players")
def player_standings():
    session = create_snowpark_session()
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

    # SQL query to select all columns from the new player focused leaderboard view
    df = session.table('GOLF_LEAGUE.APPLICATION.PLAYER_FOCUSED_LEADERBOARD_VW').select(
        "TOURNAMENT", "POSITION", "THRU", "GOLFER", "ROUND_ID", "TOTAL_SCORE_INTEGER", 
        "CURRENT_ROUND_SCORE", "PLAYER_STATUS", "TEE_TIME", "SELECTIONS", "CUT_LINE"
    ).order_by('TOTAL_SCORE_INTEGER')
    results = df.collect()

    # Query to get the name of the active tournament
    tournament_name = results[0]['TOURNAMENT'] if results else None
    
    # Get the cut line value (same for all players in the tournament)
    cut_line = results[0]['CUT_LINE'] if results else None
    
    # Get the latest timestamp from the leaderboard
    last_updated = session.table('GOLF_LEAGUE.APPLICATION.LATEST_LEADERBOARD_UPDATE_VW').select('LATEST_UPDATE','TOURNAMENT_NAME').filter(col('TOURNAMENT_NAME') == tournament_name).limit(1).collect()[0]['LATEST_UPDATE']
    last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
    session.close()

    # Start HTML response, using the tournament name
    return render_template('player_standings.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line)

@app.route("/make_picks")
def make_picks():
    session = create_snowpark_session()
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")
    tournament = 'U.S. Open'


    pick_options_df = session.table('GOLF_LEAGUE.APPLICATION.PICK_OPTIONS_VW').to_pandas()
    pick_list = pick_options_df["PLAYER"].to_list()

    # create slicers to separate out the pick lists
    first = pick_list[0:5]
    second = pick_list[5:16]
    third = pick_list[16:]

    session.close()

    return render_template('pick_form.html', tournament_name=tournament, first=first, second=second, third=third)

@app.route("/submit_picks", methods=["POST"])
def submit_picks():
    real_name = request.form.get("real_name")
    entry_name = request.form.get("entry_name")
    golfer_1 = request.form.get("golfer_1")
    golfer_2_and_3 = request.form.getlist("golfer_2_and_3")
    golfer_4_and_5 = request.form.getlist("golfer_4_and_5")

    if len(golfer_2_and_3) == 2 and len(golfer_4_and_5) == 2 and entry_name:
        golfer_2, golfer_3 = golfer_2_and_3
        golfer_4, golfer_5 = golfer_4_and_5
  
        session = create_snowpark_session()
        session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")
        tournament = 'U.S. Open'

        try:
            session.write_pandas(
                pd.DataFrame.from_dict(
                    {
                        "ENTRY_NAME": [entry_name],
                        "GOLFER_1": [golfer_1],
                        "GOLFER_2": [golfer_2],
                        "GOLFER_3": [golfer_3],
                        "GOLFER_4": [golfer_4],
                        "GOLFER_5": [golfer_5],
                        "TOURNAMENT": [tournament],
                        "REAL_NAME": [real_name]
                    }
                ),
                table_name='POOL_STAGING', database='GOLF_LEAGUE', schema='APPLICATION', overwrite=False
            )
            session.close()
            return render_template('submit_success.html', tournament=tournament,entry_name=entry_name, golfers=[golfer_1, golfer_2, golfer_3, golfer_4, golfer_5]), 200
        except Exception as e:
            session.close()
            return f"An error occurred: {e}", 500
    else:
        return "Validation Check Failed - please make sure you have 5 golfers selected and a valid entry name.", 400

if __name__ == "__main__":
    app.run(debug=True)
