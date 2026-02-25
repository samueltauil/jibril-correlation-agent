// Re-export from store.ts for backward compatibility
export { InMemoryEventStore as EventStore, classifyEvent, resolveRepo } from "./store.js";
export type { IEventStore } from "./store.js";
