First We need to BUILD imgaes
Move to current Directory
Run -> docker build -t bugsbd_lab .
Run this command to view the created images -> docker ps -a
Create and Run Container -> docker run --name lab -p '80:80' -p '2222:22' -d bugsbd_lab:latest


OR JUST Simple run the install.cmd or install.sh in the previous directory