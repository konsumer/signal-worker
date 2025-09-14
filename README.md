Cloudflare worker broadcast websocket server.

The idea here is that any message you send to the server gets echoed to all the other clients.

I originally made it for [reticulum-webrtc](https://github.com/konsumer/reticulum-webrtc), but the idea of the clients doing their own routing is a generally useful thing. You could use this for a chat or game system, where all the clients need to have a copy of everything.

This operates with a concept of app-rooms. You connect to a path, and all other clients that connect to the same path will get broadcast-messages from it, like: `wss://signal.konsumer.workers.dev/ws/myapp`

There is also an example client [here](https://signal.konsumer.workers.dev/).

I have one deployed at `wss://signal.konsumer.workers.dev`, that you can use, but you can feel free to deploy your own:

```sh
npm run deploy
```
