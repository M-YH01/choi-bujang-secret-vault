// 오프라인 안내용 서비스 워커입니다. 보관하는 것은 정적 안내 페이지와 아이콘뿐입니다.
// /api, /aleph.json, /data.json 등 자료·로그인·기기 승인 요청은 가로채지도 보관하지도 않습니다.
// 따라서 오프라인에서는 보호 자료가 보이지 않고, 이 파일에는 토큰이나 기기 키가 없습니다.
const CACHE = 'shell-v1';
const SHELL = ['/offline.html', '/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);
  // 페이지 이동이 아닌 요청(API·데이터·스크립트 등)은 건드리지 않습니다.
  if (request.method !== 'GET' || request.mode !== 'navigate' || url.origin !== self.location.origin) return;
  // 페이지는 항상 네트워크에서 가져오고, 연결이 없을 때만 안내 페이지를 보여 줍니다.
  event.respondWith(fetch(request).catch(async () => (await caches.match('/offline.html')) ?? Response.error()));
});
