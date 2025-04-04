import folium
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

@app.route('/')
def map_view():
    """Render the map."""
    # Create a folium map centered at a default location
    world_map = folium.Map(location=[0, 0], zoom_start=2)

    # Add a click event to capture latitude and longitude
    world_map.add_child(folium.LatLngPopup())

    # Save the map as an HTML file
    map_html = world_map._repr_html_()

    # Render the map in a simple HTML template
    template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Interactive World Map</title>
    </head>
    <body>
        <h1>Click on the map to get coordinates</h1>
        {map_html}
    </body>
    </html>
    """
    return render_template_string(template)

if __name__ == "__main__":
    print("Starting the server... Open http://127.0.0.1:5000 in your browser.")
    app.run(debug=True)