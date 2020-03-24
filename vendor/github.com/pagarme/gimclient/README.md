# gimclient

gimclient is a Go client library for accessing the [GIM](https://gim.readme.io/v2.0) API v2.0

## Table of Contents

- [Technology](#technology)
- [How it works](#how-it-works)
- [How to run](#how-to-run)

## Technology

- [Golang](https://golang.org/doc/) 1.11.14

## How it works

Dashboard Admin Access is a wrapper for the [GIM](https://gim.readme.io/v2.0) API v2.0. The current implemented functionalities are:

- Create a new client:

 ```golang
 client = NewClient(apikey, appkey)
 ```

- Get user

```golang
 client.Getuser(email)
```

- Generate secret

```golang
 secret = client.GenerateSecret()
```

- Add user to application

 ```golang
 client.AddUserToApp(email, name, secret)
 ```

- Add role to user

 ```golang
 client.AddRoleToUser(email, name, role)
 ```

## How to run

This is not a runnable package, you should use it as a library instead.
