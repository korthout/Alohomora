# Alohomora [![Build Status](https://travis-ci.org/korthout/Alohomora.svg?branch=master)](https://travis-ci.org/korthout/Alohomora) [![Coverage Status](https://coveralls.io/repos/github/korthout/Alohomora/badge.svg?branch=master)](https://coveralls.io/github/korthout/Alohomora?branch=master) [![Code Climate](https://lima.codeclimate.com/github/korthout/Alohomora/badges/gpa.svg)](https://lima.codeclimate.com/github/korthout/Alohomora)
A simple [Dropwizard](https://github.com/dropwizard/dropwizard) project that I use to learn more about web service development using modern Java.

# Features
- Users can register themselves as a customer, provider or admin (role).
- Users can login with their credentials.
- Logged-in providers can create advertisements.

# Some technical choices
- Data is stored in a MySQL database.
- Communication to the database is handled via [JDBI](http://jdbi.org/) interfaces.
- User authentication is handled via JSON Web Tokens (JWT) using [dropwizard-auth-jwt](https://github.com/ToastShaman/dropwizard-auth-jwt).

# Continous integration
- [Travis-CI](https://travis-ci.org/) facilitates containerized building and testing.
- [Maven](https://maven.apache.org/) configures builds and provides dependency management.
- [JUnit](http://junit.org/) for automated unit tests.
- [Mockito](http://site.mockito.org/) mocks dependencies in unit tests.
- [JaCoCo](https://github.com/jacoco/jacoco) checks the code coverage.
- [Coveralls](https://coveralls.io/) publishes the code coverage.

# License
Apache License Version 2.0

http://apache.org/licenses/LICENSE-2.0.txt
