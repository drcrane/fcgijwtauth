# Simple Cookie and Authorisation for nginx

This application uses FastCGI to verify JWTs that are presented to the server
via a cookie or in an `Authorization` header.

### Building

    mkdir build
    cmake -GNinja -DCMAKE_BUILD_TYPE=debug -Bbuild .
    ninja -C build/

See also `runauth.sh`.

### Configuring Nginx

Below is a brief configuration fragment from a `server` section in nginx:

    location /private {
        alias /var/www/localhost/private_htdocs;
        auth_request /authmain;
        autoindex on;
    }
    
    location /authmain {
        client_max_body_size 1M;
        alias /var/www/localhost/auth_htdocs;
        try_files $uri @authmain;
    }
    
    location @authmain {
        include fastcgi_params;
        fastcgi_split_path_info "^(/authmain/)(.+)$";
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        fastcgi_param SCRIPT_FILENAME $fastcgi_script_name;
        fastcgi_pass unix:/run/spawn-fcgi/authmain.sock-1;
    }

`/var/www/localhost/auth_htdocs` is a location where some resources
can be kept (I am not sure how useful these are yet).

### Executing

The script `runauth.sh` should be sufficient, ensure it is executing in the
project root directory and the `doas` tool is available and configured
on the system.

### Accessing the `/private` URL

The private URL should present itself as "401 Unauthorized" when there is no
appropriate `auth` cookie set. Verify by visiting the URL. If this is the case
access can be granted by setting a cookie to a valid JWT. Assuming the
configuration is similar to the above the following steps should allow access:

* Generate a JWT with the `jwt_creator` tool:

    build/jwt_creator --name "Example User" --email user@example.com

* Visit `/authmain/auth_cookies.html`
* Enter the generated JWT into the **Cookie Value:** box and click **Set
  Cookie** (the other values on this form have appropriate defaults)
* Now that the cookie is set it should be possible to access pages below
  the `/private` URL.

### picojson

`picojson` puts too many escape characters in... there is an open pull request
but it seems unmaintained :-(, see `include/picojson/picojson.h` in the MAP
section.

* [github pull request 152](https://github.com/kazuho/picojson/pull/152)

### OAuth/OpenIDConnect Discovery Documents

* `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
* `https://accounts.google.com/.well-known/openid-configuration`
* `https://api.login.yahoo.com/.well-known/openid-configuration`
* `https://testingid.e42.uk/.well-known/openid-configuration`
