# Alohomora [![Build Status](https://travis-ci.org/korthout/Alohomora.svg?branch=master)](https://travis-ci.org/korthout/Alohomora) [![Coverage Status](https://coveralls.io/repos/github/korthout/Alohomora/badge.svg?branch=master)](https://coveralls.io/github/korthout/Alohomora?branch=master) [![Code Climate](https://lima.codeclimate.com/github/korthout/Alohomora/badges/gpa.svg)](https://lima.codeclimate.com/github/korthout/Alohomora)
A simple [Dropwizard](https://github.com/dropwizard/dropwizard) project that I use to learn more about web service development using modern Java.

# Features
- Users can register themselves as a customer, provider or admin (role).
- Users can login with their credentials.
- Logged-in providers can create advertisements.

# Structure
This project is setup using the recommended maven module separation:
> `project-api` should contain your Representations; `project-client` should use those classes and an HTTP client to implement a full-fledged client for your application, and `project-application` should provide the actual application implementation, including Resources.

I've chosen for the simplyfied naming: `api`, `client` and `application`. However, at the moment application is the only module with actual code. I still want to split api from implementation. The application uses the following package structure.

- `api`: Representations
- `auth`: Authentication
- `core`: Domain implementation
- `db`: Database access
- `resources`: RESTful API resources
- `utilities`: I know... I know...
- `Alohomora`: The application class
- `AlohomoraConfiguration`: Application configuration

# Some technical choices
- Data is stored in a MySQL database.
- Communication to the database is handled via [JDBI](http://jdbi.org/) interfaces.
- User authentication is handled via JSON Web Tokens (JWT) using [dropwizard-auth-jwt](https://github.com/ToastShaman/dropwizard-auth-jwt).

# Continous integration
- [Travis-CI](https://travis-ci.org/) facilitates containerized building and testing.
- [Maven](https://maven.apache.org/) manages dependencies and configures builds.
- [JUnit](http://junit.org/) helps automate unit tests.
- [Mockito](http://site.mockito.org/) mocks dependencies in unit tests.
- [JaCoCo](https://github.com/jacoco/jacoco) checks the code coverage.
- [Coveralls](https://coveralls.io/) publishes the code coverage.
- [Code Climate](https://codeclimate.com/) evaluates the code quality.

# License
Apache License Version 2.0

http://apache.org/licenses/LICENSE-2.0.txt
