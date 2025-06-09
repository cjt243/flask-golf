from pytz import timezone
from flask import Flask, render_template, request, redirect, url_for, g
import pandas as pd
from flask_compress import Compress
from snowflake.snowpark import Session
from snowflake.snowpark.functions import col
import os
import base64
import time
try:
    from config import *
except ModuleNotFoundError:
    pass  # Using environment variables in production

app = Flask(__name__) 
Compress(app)

# Global session cache
_snowpark_session = None
_session_created_at = None
SESSION_TIMEOUT = 3600  # 1 hour

# Simple in-memory cache with TTL
_cache = {}
CACHE_TTL = 300  # 5 minutes

def get_cached(key):
    """Get cached data if it exists and hasn't expired"""
    if key in _cache:
        data, timestamp = _cache[key]
        if time.time() - timestamp < CACHE_TTL:
            return data
        else:
            del _cache[key]
    return None

def set_cache(key, data):
    """Set cached data with current timestamp"""
    _cache[key] = (data, time.time())

def get_snowpark_session():
    """Get or create a Snowpark session with caching"""
    global _snowpark_session, _session_created_at
    
    current_time = time.time()
    
    # Check if we need to create a new session
    if (_snowpark_session is None or 
        _session_created_at is None or 
        current_time - _session_created_at > SESSION_TIMEOUT):
        
        if _snowpark_session:
            try:
                _snowpark_session.close()
            except:
                pass
        
        _snowpark_session = create_snowpark_session()
        _session_created_at = current_time
    
    return _snowpark_session



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
    # Check cache first
    cached_data = get_cached('leaderboard_data')
    if cached_data:
        results, tournament_name, last_updated, cut_line, player_scores = cached_data
        return render_template('leaderboard.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line, player_scores=player_scores)
    
    session = get_snowpark_session()
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

    # SQL query to select all columns from the leaderboard view
    df = session.table('GOLF_LEAGUE.APPLICATION.LEADERBOARD_DISPLAY_DETAILED_VW').select("RANK","ENTRY_NAME","TOURNAMENT","TEAM_SCORE","PICKS").order_by('RANK')
    results = df.collect()
    # Query to get the name of the active tournament
    # tournament_name = results[0]['TOURNAMENT'] if results else None
    tournament_name = 'PGA Championship'
    

    
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

    except:
        cut_line = None
        player_scores = {}
    
    # Get the latest timestamp from the leaderboard
    last_updated = session.table('GOLF_LEAGUE.APPLICATION.LATEST_LEADERBOARD_UPDATE_VW').select('LATEST_UPDATE','TOURNAMENT_NAME').filter(col('TOURNAMENT_NAME') == tournament_name).limit(1).collect()[0]['LATEST_UPDATE']
    last_updated = last_updated.replace(tzinfo=timezone('UTC')).astimezone(timezone('US/Eastern')).strftime('%A %B %d @ %I:%M %p %Z')
    
    # No longer closing session since we're reusing it
    
    # Cache the data
    set_cache('leaderboard_data', (results, tournament_name, last_updated, cut_line, player_scores))
    
    # Start HTML response, using the tournament name
    return render_template('leaderboard.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line, player_scores=player_scores)

@app.route("/players")
def player_standings():
    # Check cache first
    cached_data = get_cached('player_standings_data')
    if cached_data:
        results, tournament_name, cut_line, last_updated = cached_data
        return render_template('player_standings.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line)
    
    session = get_snowpark_session()
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
    
    # No longer closing session since we're reusing it
    
    # Cache the data
    set_cache('player_standings_data', (results, tournament_name, cut_line, last_updated))

    # Start HTML response, using the tournament name
    return render_template('player_standings.html', tournament_name=tournament_name, results=results, last_updated=last_updated, cut_line=cut_line)

@app.route("/make_picks")
def make_picks():
    tournament = 'U.S. Open'
    
    # Check cache first
    cached_data = get_cached('pick_options_data')
    if cached_data:
        first, second, third = cached_data
        return render_template('pick_form.html', tournament_name=tournament, first=first, second=second, third=third)
    
    session = get_snowpark_session()
    session.query_tag = os.getenv("SNOWFLAKE_QUERY_TAG")

    pick_options_df = session.table('GOLF_LEAGUE.APPLICATION.PICK_OPTIONS_VW').to_pandas()
    pick_list = pick_options_df["PLAYER"].to_list()

    # create slicers to separate out the pick lists
    first = pick_list[0:5]
    second = pick_list[5:16]
    third = pick_list[16:]
    
    # Cache the data
    set_cache('pick_options_data', (first, second, third))

    # No longer closing session since we're reusing it

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
  
        session = get_snowpark_session()
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
            # No longer closing session since we're reusing it
            return render_template('submit_success.html', tournament=tournament,entry_name=entry_name, golfers=[golfer_1, golfer_2, golfer_3, golfer_4, golfer_5]), 200
        except Exception as e:
            # No longer closing session since we're reusing it
            return "An error occurred while submitting your picks. Please try again.", 500
    else:
        return "Validation Check Failed - please make sure you have 5 golfers selected and a valid entry name.", 400

@app.route("/health")
def health_check():
    """Health check endpoint with performance metrics"""
    return {
        "status": "healthy",
        "cache_count": len(_cache),
        "timestamp": time.time()
    }

@app.route("/clear_cache")
def clear_cache():
    """Clear all cached data"""
    global _cache
    _cache.clear()
    return {"status": "cache cleared", "timestamp": time.time()}

if __name__ == "__main__":
    app.run()
