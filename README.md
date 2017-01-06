# Project: Multi User Blog

This project is an extension of a project started in the [Intro to Backend](https://www.udacity.com/course/intro-to-backend--ud171) course. In that course, students build a multi user blog application using [Google App Engine](https://cloud.google.com/appengine/). However, certain features needed to complete this project were left out of the course.

You can view the live site at [Full Stack Jedi Blog](http://full-stack-jedi-blog.appspot.com/)

## Getting Started

These instructions will show you how to run the application locally.

### Prerequisites

* [Google App Engine](https://cloud.google.com/appengine/docs/python/download)
* [Python 2.7](https://www.python.org/downloads/release/python-2713/)

### Installing
1. Clone the repo by running the following command from the command prompt
  1. `$ git clone https://github.com/jefferygraham992/FSND-Project-Multi-User-Blog.git`
2. cd to the blog application directory
  1. `$ cd /FSND-Project-Multi-User-Blog`
3. Install [Cloud SDK installer](https://cloud.google.com/sdk/docs/)
  1. Launch the installer and follow the prompts. If Python 2.7 is not installed on your system, make sure the option to install **Bundled Python** is checked.
  2. After installation has completed, accept the following options:
      * Start Cloud SDK Shell
      * Run gcloud init
  3. The default installation does not include the App Engine extensions required to deploy an application using **gcloud** commands. These components can be installed using the [Cloud SDK component manager](https://cloud.google.com/sdk/docs/managing-components)
      * To install Google App Engine, run `gcloud components install app-engine-python`
4. Run  _dev_appserver.py ._ from the blog application directory: `FSND-Project-Multi-User-Blog $ dev_appserver.py .`
5. Access the application at [http://localhost:8080/](http://localhost:8080/)



