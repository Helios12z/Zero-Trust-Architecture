FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --only=production

COPY server.js ./

EXPOSE 3000

CMD [ "node", "server.js" ]
