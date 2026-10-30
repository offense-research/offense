// Queue consumer. The destination and token are injected as Worker secrets.
export default {
  async queue(batch, env) {
    const messages = batch.messages.map(message => ({ ...message.body, queueMessageId: message.id }));
    const response = await fetch(env.PURPLE_INGEST_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${env.PURPLE_INGEST_TOKEN}`
      },
      body: JSON.stringify({ events: messages })
    });
    if (!response.ok) throw new Error(`Purple ingest returned HTTP ${response.status}`);
  }
};
