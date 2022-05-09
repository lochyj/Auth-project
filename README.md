# JWT and NODE JS Auth

## .ENV?

    The env file has some example secrets
    If you intend to use this please generate your own

## Prerequisites

    * Node.js
    * MongoDB client or MongoDB atlas

## Starting

1. `npm i`
2. create a file called .env with the following content:

    ``` env
        REFRESH_TOKEN_SECRET = 'your-token-here'
        ACCESS_TOKEN_SECRET = 'you-other-token-here'
        ACCESS_TOKEN_TIME = '10m'
    ```

3. `npm run dev`
4. open the browser and go to <http://localhost/>

## Docs

### Registering an account

    ```js
    fetch('http://localhost/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: 'your-username',
            password: 'your-password'
    })
    })
    ```
