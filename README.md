# laravel_nodejsWS_sessionAuth
Laravel's session authentication in Nodejs Websocket server

### Dependencies
- ioredis  *(Laravel session should be stored here for easier access from nodejs)*
- php-serialize
- mariadb
- cookie
- Laravel's .env file *(please see the sample .env file in the /example to know what are necessary fields in .env)*


### Note
- This is working on Laravel v9, other versions of Laravel have not been tested.
- You do not literally have to use websocket server to use this. (I think so, I have not really tried with nodejs http server).

### Inspiration
I was making a website, using Laravel, that can run real-time auction. I use Nodejs ws as a Websocket server but then I realize there is no built-in mechanics for me to authenticate users connecting to Websocket server when they enter the auction page. So I dive into the source code of Laravel and findout how they encrypt and decrypt the session id and store them in the cookies, so I re-implemented in Nodejs to perform session authentication whenever there is a connection to the Websocket server.

### Installation
You just need to download the ***/src/laravel.js*** file, feel free to modify it to make it compatible to your project. 
<br>
In my project, I use redis and mariadb so I also use those two as connector in ***/src/laravel.js***

### Example
Take a look at ***/example***, specifically ***example.js** for my use case.

### Question
Should you have any question or need help with using this in your project, contact me at: tranleanhquan6309@gmail.com

