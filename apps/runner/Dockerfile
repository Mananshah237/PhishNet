FROM mcr.microsoft.com/playwright:v1.50.0-jammy

WORKDIR /runner

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .

# Runner writes artifacts to /out by convention
VOLUME ["/out"]

CMD ["node", "run.js"]
