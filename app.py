from flask import Flask
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
    # Query to get the name of the active tournament
    tournament_query = "SELECT EVENT FROM GOLF_LEAGUE.ANALYTICS.TOURNAMENTS WHERE ACTIVE_TOURNAMENT = TRUE"
    tournament_name = session.sql(tournament_query).collect()[0][0]  # Assuming there is always one active tournament

    # SQL query to select all columns from the leaderboard view
    df = session.sql("SELECT * FROM GOLF_LEAGUE.ANALYTICS.LEADERBOARD_DISPLAY_VW ORDER BY RANK")
    results = df.collect()
    session.close()

    # Start HTML response, using the tournament name
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{tournament_name}</title>
        <!-- Include Bootstrap CSS -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ background-color: #343a40; color: #f8f9fa; }} /* Dark background and light text */
            .leaderboard-header {{
                background-color: #495057; /* Darker grey */
                border-radius: 0 0 0 0;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                padding: 20px;
                display: flex;
                align-items: center;
                cursor: pointer;
                margin-bottom: 2px; /* Adds a small gap between rows */
            }}
            .leaderboard-header:nth-child(odd) {{
                background-color: #40484f; /* Slightly different grey for alternate rows */
            }}
            .leaderboard-content {{
                background-color: #495057; /* Darker grey */
                border-radius: 0 0 0 0;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                overflow: hidden;
                max-height: 0;
                transition: max-height 0.5s ease-out;
                justify-content: center;
                align-items: center;
                flex-direction: column;
            }}
            .leaderboard-icon {{
                width: 30px;
                height: 30px;
                margin-right: 15px;
                cursor: pointer;
            }}
            .leaderboard-score {{
                margin-left: auto;
                font-weight: bold;
            }}
            .chip {{
                display: inline-block;
                background-color: #6c757d; /* Lighter grey */
                border-radius: 10px;
                padding: 5px 10px;
                margin: 2px;
                cursor: pointer;
            }}
            .chip.highlight {{
                background-color: #28a745; /* Bootstrap green */
            }}
            .rank {{
                font-size: 1.5em;
                margin-right: 15px;
            }}
    </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                document.querySelectorAll('.leaderboard-header').forEach(header => {{
                    header.addEventListener('click', function() {{
                        const content = this.nextElementSibling;
                        if (content.style.maxHeight && content.style.maxHeight !== '0px') {{
                            content.style.maxHeight = '0';
                        }} else {{
                            content.style.maxHeight = content.scrollHeight + 'px';
                        }}
                        this.querySelector('.leaderboard-icon').classList.toggle('fa-chevron-up');
                        this.querySelector('.leaderboard-icon').classList.toggle('fa-chevron-down');
                    }});
                }});
                document.querySelectorAll('.chip').forEach(chip => {{
                    chip.addEventListener('click', function(event) {{
                        event.stopPropagation(); // Prevent the leaderboard from toggling
                        const isSelected = this.classList.contains('highlight');
                        const chipValue = this.textContent.trim();
                        document.querySelectorAll('.chip').forEach(c => {{
                                                    // Remove highlight from all chips before reapplying to new selection
                            c.classList.remove('highlight');
                        }});
                        if (!isSelected) {{
                            document.querySelectorAll('.chip').forEach(c => {{
                                if (c.textContent.trim() === chipValue) {{
                                    c.classList.add('highlight');
                                }}
                            }});
                        }}
                    }});
                }});
            }});
        </script>
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="mb-4">{tournament_name}</h1>
    '''

    # Append entries to the HTML
    for row in results:
        selections_chips = ''.join(f'<span class="chip">{selection.strip()}</span>' for selection in row.SELECTIONS.split(','))
        html += f'''
            <div class="leaderboard-header">
                <div class="rank">{row.RANK}</div>
                <i class="fas fa-chevron-down leaderboard-icon"></i>
                <div>{row.ENTRY_NAME}</div>
                <div class="leaderboard-score">{row.TEAM_SCORE}</div>
            </div>
            <div class="leaderboard-content">
                <div>{selections_chips}</div>
            </div>
        '''
    # Close the HTML tags
    html += '''
        </div>
    </body>
    </html>
    '''
    return html

# if __name__ == "__main__":
#     app.run(debug=True)
