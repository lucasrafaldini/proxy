# **MiddleMan**
![DjangoREST](https://img.shields.io/badge/DJANGO-REST-ff1709?style=for-the-badge&logo=django&logoColor=white&color=ff1709&labelColor=gray)
![Django](https://img.shields.io/badge/django-%23092E20.svg?style=for-the-badge&logo=django&logoColor=white)
![Postgres](https://img.shields.io/badge/postgres-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

Proxy service built with Django, DRF and PostgreSQL.

- [**MiddleMan**](#middleman)
  - [**Explanation**](#explanation)
  - [**Endpoints**](#endpoints)
    - [**Quick Run**](#quick-run)
    - [**Testing**](#testing)
    - [**Formatting**](#formatting)
  - [Contributing](#contributing)
    - [Step 1](#step-1)
    - [Step 2](#step-2)
    - [Step 3](#step-3)
    - [TO-DO's](#to-dos)
  - [License](#license)


## **Explanation**
You define a base url (which is your target) and request from proxy address all paths you want from your target.

Example:

Let's say you have a target url: `http://www.example.com/` and you want to proxy all paths from this url. So, you define `http://www.example.com/` as your `.env` variable `BASE_TARGET_URL`. Now, you just redirect all requests to the URL your proxy is using, indicating the path you want to proxy.

So, if the proxy is hosted at `https://awesome-proxy.com/` and you want to access `http://example.com/assets/images` you just send a `GET` request to `https://awesome-proxy.com/assets/images` and you will get the response from `http://example.com/assets/images` __streamed from the server__.

The service will register your `IP Address` and the path you want to access and filter your access based on the `max_requests` and `already_requested` saved in the database for your registered key (an unique hash string with 20 characters made with a combination of your IP + @ + the path you tried to access). In case you don't have a key registered, the service will register it with a default value for `max_requests`(100) and `already_requested`(0).


## **Endpoints**

You find the endpoints' method, url, body and description in the table bellow.

| Method | Endpoint url | Body | Description |
| ------ | ---------------- |---------- |-------------------------------------------------------------------------------- |
| `GET`  | `/proxy/{path}`  |                  | Returns desired path content as a stream, registering your IP address and the path you tried to access. | 
| `GET`  | `/registry`  |                  | List all access entry register paginated                                  |
| `GET`  | `/registry`  |    `{"key": "access_entry_key"}`              | List one access entry register  |
| `PATCH`  | `/registry`  |  `{"key": "access_entry_key", "action": "update_max_requests", "max_requests": "999"}`    | Update max requests allowed for the desired access entry indexed by its key |
| `PATCH`  | `/registry`  | `{"key": "access_entry_key", "action": "reset_already_requested"}` | Reset already_requested field for the desired access entry indexed by its key |
### **Quick Run**

Setup you local .env file:

```bash
$ cp .env.example .env
```

Edit .env file with your settings:

`BASE_TARGET_URL` should be the target url you want to proxy;

`SECRET_KEY` is the Django secret key;

`LOGLEVEL` is the log level you want to use;

`DATABASE_URI` is the database URI

`POSTGRES_USER` is the Postgres user;

`POSTGRES_PASSWORD` is the Postgres password;

`POSTGRES_DB` is the Postgres database;

`POSTGRES_HOST` is the Postgres host;

Use the Makefile to build, run and even test the project:

For building please use:
```bash
$ make build-and-run
```

If you just want to run the project:
```bash
$ make run
```


### **Testing**

To run the tests, you can also use Makefile:

```bash
$ make test
```

### **Formatting**

To run black and isort, you can also use Makefile:

```bash
$ make format
```

----------------------------------------------------------------

---

## Contributing

> Feel free to contribute, but before you get to work, take a look at our issues to make sure you are not going to do something someone else is already doing. Feel free to add some issues if you find any bug or if you think I should add some funcionality.

> To start coding this project follow these steps:

### Step 1

- **Option 1**

  - 🍴 Fork this repo!

- **Option 2**
  - 👯 Clone this repo to your local machine using `https://github.com/lucasrafaldini/proxy.git`

### Step 2

- **CODE LIKE THERE'S NO TOMORROW!** 🔨🔨🔨

### Step 3

- 🔃 Create a new pull request using <a href="https://github.com/lucasrafaldini/proxy/compare/" target="_blank">`https://github.com/lucasrafaldini/proxy/compare/`</a>.

---

### TO-DO's

- [ ] Make key a url parameter in individual acces entry endpoint;
- [ ] Implement a cache system;
- [ ] Also get UserAgent info and make it a filtering criterium;
- [ ] Add a Postman/Insomnia collection to be avaiable for testing;
- [ ] Implement a way to make a blacklist of paths and IPs to avoid;
- [ ] Implement a  stress test with around 50k requests per second in each endpoint (maybe use [Locust](https://locust.io/));
- [ ] Add AsyncIO + cache to make 50k requests/s charge possible;
- [ ] Implement multithreads and multiprocessing to make 50k requests/s charge possible;

---

## License


[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)
