echo WW91IEdvdCBNZQ== | base64 -d > /var/www/html/flag.txt
cd /var/www/html
python3 -m http.server -b 127.0.0.1 8000 &
cd /app
service ssh start
python3 Main.py