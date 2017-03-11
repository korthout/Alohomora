# Alohomora [![Build Status](https://travis-ci.org/korthout/Alohomora.svg?branch=master)](https://travis-ci.org/korthout/Alohomora) [![Coverage Status](https://coveralls.io/repos/github/korthout/Alohomora/badge.svg?branch=master)](https://coveralls.io/github/korthout/Alohomora?branch=master)
A simple Dropwizard project that I use to learn more about web service development using modern Java.

# Features
- Users can register themselves as customer, provider or admin.
- Users can login with their credentials.
- Logged-in providers can create advertisements.

# Some technical choices
- Data is stored in a MySQL database.
- Communication to the database is handled via JDBI interfaces.
- User authentication is handled via JSON Web Tokens (JWT).
- User authorization is handled via Role class.

# License
Apache License Version 2.0

http://apache.org/licenses/LICENSE-2.0.txt
