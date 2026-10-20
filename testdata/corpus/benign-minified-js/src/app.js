'use strict';

const isProd = process.env.NODE_ENV === 'production';
const base = isProd ? 'https://api.example.test' : 'http://localhost:3000';

async function loadItems() {
  const res = await fetch(`${base}/items`);
  if (!res.ok) throw new Error(`status ${res.status}`);
  return res.json();
}

loadItems().then((items) => console.log(items.length));
