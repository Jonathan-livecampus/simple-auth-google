## Run with docker

##### Requirements

Install docker (docker-compose might be needed on linux).

- Install docker on [windows](https://docs.docker.com/desktop/install/windows-install/) 
- Install docker on [macos](https://docs.docker.com/desktop/install/mac-install/) 
- Install docker on [ubuntu](https://docs.docker.com/engine/install/ubuntu/) 

##### How to run

```bash
docker-compose up

#Add '-d' to run in background
docker-compose up -d
```

##### More infos about docker

Docker command line cheat sheet 
https://docs.docker.com/get-started/docker_cheatsheet.pdf

## Run without docker

##### Requirements

Install Node.js 18.17 or later.
https://nextjs.org/docs/getting-started/installation

Install mongodb and configure it.

- Install mongodb on [windows](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-windows/) 
- Install mongodb on [macos](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/) 
- Install mongodb on [ubuntu](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/) 


##### How to run

```bash
npm run dev

#Or with yarn
yarn dev

#Or with bun
bun dev
```

## How to use it

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

## Learn More

- [Next.js doc](https://nextjs.org/docs) - learn about Next.js features and API.
- [NextAuth.js doc](https://next-auth.js.org/getting-started/example) - an easy way to handle auth on Next.js app
- [Next.JS en 5 minutes](https://www.youtube.com/watch?v=Q5W5FYFzcEk&t=302s) - video fr
- [Typescript cheat sheet](https://devhints.io/typescript) 
- [React cheat sheet](http://cheatsheets.shecodes.io/react)
