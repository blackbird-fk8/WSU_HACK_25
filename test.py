import pandas as pd
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

"""import random
import math

def main():
    # Get user input for latitude, longitude, and radius
    lat = float(input("Enter latitude: "))
    lon = float(input("Enter longitude: "))
    radius_km = float(input("Enter radius (km): "))

    # Call the generate_masked_location function
    masked_lat, masked_lon = generate_masked_location(lat, lon, radius_km)
    
    # Print the results
    print(f"Original Location: Latitude = {lat}, Longitude = {lon}")
    print(f"Masked Location: Latitude = {masked_lat}, Longitude = {masked_lon}")

def generate_masked_location(lat, lon, radius_km):
    radius_deg = radius_km / 111  # Approx conversion: 1° lat ≈ 111 km

    u = random.random()
    v = random.random()
    w = radius_deg * math.sqrt(u)
    t = 2 * math.pi * v
    delta_lat = w * math.cos(t)
    delta_lon = w * math.sin(t) / math.cos(math.radians(lat))
    
    masked_lat = lat + delta_lat
    masked_lon = lon + delta_lon
    return masked_lat, masked_lon

if __name__ == "__main__":
    main()"""