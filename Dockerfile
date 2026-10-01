# syntax=docker/dockerfile:1

# ---- 依赖层：源码与测试共用的构建环境 ----
FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# ---- 一次性验收：类型检查 + 全部测试 + 生产构建 ----
FROM deps AS verify
COPY . .
CMD ["npm", "run", "verify"]

# ---- 静态资源构建 ----
FROM deps AS build
COPY . .
RUN npm run build

# ---- 运行镜像：nginx 托管静态页面（数据只存在浏览器里） ----
FROM nginx:1.27-alpine AS app
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
