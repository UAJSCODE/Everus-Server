import type { WebSocket } from "ws";

export class EventHub {
  private readonly connections = new Map<string, Set<WebSocket>>();

  add(deviceId: string, socket: WebSocket) {
    const sockets = this.connections.get(deviceId) ?? new Set<WebSocket>();
    sockets.add(socket);
    this.connections.set(deviceId, sockets);
  }

  remove(deviceId: string, socket: WebSocket) {
    const sockets = this.connections.get(deviceId);
    sockets?.delete(socket);
    if (sockets?.size === 0) this.connections.delete(deviceId);
  }

  send(deviceId: string, event: unknown) {
    const sockets = this.connections.get(deviceId);
    if (!sockets?.size) return false;
    const payload = JSON.stringify(event);
    for (const socket of sockets) {
      if (socket.readyState === 1) socket.send(payload);
    }
    return true;
  }

  isOnline(deviceId: string) {
    return (this.connections.get(deviceId)?.size ?? 0) > 0;
  }
}
