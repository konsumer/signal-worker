import { DurableObject } from 'cloudflare:workers'

// Worker
export default {
  async fetch(request, env, ctx) {
    const u = new URL(request.url)

    if (!u.pathname.startsWith('/ws')) {
      // trigger static assets
      return new Response('NO', { status: 404 })
    }

    const ws = env.WEBSOCKET_SERVER.getByName(u.pathname)
    return ws.fetch(request)
  }
}

// Durable Object Manager that tracks connected clients and broadcasts messages
export class WebSocketServer extends DurableObject {
  async fetch(request) {
    const webSocketPair = new WebSocketPair()
    const [client, server] = Object.values(webSocketPair)
    this.ctx.acceptWebSocket(server)
    return new Response(null, {
      status: 101,
      webSocket: client
    })
  }

  async webSocketMessage(ws, message) {
    for (const c of this.ctx.getWebSockets()) {
      if (c != ws) {
        c.send(message)
      }
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
    ws.close(code, 'Durable Object is closing WebSocket')
  }
}
