# build app
FROM node:21-slim As development

WORKDIR /app

COPY package*.json .

RUN npm install

COPY . .

RUN npm run build

# run builded app
FROM node:21-slim As production

ARG NODE_ENV=prod
ENV NODE_ENV=${NODE_ENV}

WORKDIR /app

COPY --from=development /app/dist ./dist
COPY --from=development /app/package*.json .
COPY --from=development /app/*.env .

RUN npm install

CMD ["npm", "run", "start:prod"]