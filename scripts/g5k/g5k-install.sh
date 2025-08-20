sudo-g5k apt update 
sudo-g5k apt upgrade -y
sudo-g5k apt install nginx socat -y
sudo-g5k pip install locust
sudo-g5k pip install psutil
sudo-g5k pip install psrecord
chmod +x scripts/*