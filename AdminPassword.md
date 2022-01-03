## Create User/Password
Next, run htpasswd command to create a user that will be given access to your website. Replace developer below with your choice of username.
````
htpasswd -c /etc/nginx/conf.d/.htpasswd developer
````

We use -c option to specify password file location. When you press enter, you will be prompted for a password.

For example, when we create another user, we don’t specify password file location.

````
htpasswd /etc/nginx/conf.d/.htpasswd developer2
````

## Open NGINX configuration file
Open terminal and run the following command to open NGINX server configuration file.

´´´´
sudo nano /etc/nginx/nginx.conf
´´´´
If you have configured separate virtual hosts for your pool (e.g www.example.com), such as /etc/nginx/sites-enabled/website.conf then open its configuration with the following command

````
sudo nano /etc/nginx/sites-enabled/website.conf
````
Find inside the text:
````
location / {
        try_files $uri $uri/ /index.php?$args;
        }
        location @rewrite {
        rewrite ^/(.*)$ /index.php?r=$1;
        }
````



change admin for your folder name for administration and add :
````
location /admin/ {
    auth_basic "Restricted Access!";
    auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
    
}
````
them execute Control + X and save

Like that youcan configure basic authentication for specific web directories/subdirectories (e.g /admin) by adding auth_basic and auth_basic_user_file directives in a location block for that directory.

Run the following command to check syntax of your updated config file.

````
sudo nginx -t
````

If there are no errors, run the following command to restart NGINX server.

````
sudo service nginx reload

````
Now is protected your admin folder
