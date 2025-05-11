import './env.js';
import { WebSocketServer } from "ws";
import {parse} from "url";
import { Laravel } from "../src/laravel.js";


const wss = new WebSocketServer({ 
    port: 8080, 
    host: "localhost",
    clientTracking: true
});

wss.on("connection", function connection(ws, request) { 
    const parameters = parse(request.url, true).query;
    // Perform session authentication.
    Laravel.auth(request.headers.cookie, parameters.id)
    .then((result) => {
        if (result){
            // Authenticanted successfully
            // Do something
            do_something();
        }
        else {
            // Authentication fails
            do_otherthing();
        }
    })
    .catch(() => {
        ws.terminate();
    });
});
