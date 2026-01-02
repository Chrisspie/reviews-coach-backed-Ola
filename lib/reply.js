export const unauthorized = (reply, msg = 'Unauthorized') => reply.code(401).send({ error: msg });
export const forbidden = (reply, msg = 'Forbidden') => reply.code(403).send({ error: msg });
export const badRequest = (reply, msg = 'Bad Request') => reply.code(400).send({ error: msg });
