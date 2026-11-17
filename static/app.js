const steps = [...document.querySelectorAll('.step')];
const progress = [...document.querySelectorAll('.progress-step')];
const startForm = document.querySelector('#start-form');

function showStep(number) {
  steps.forEach((step) => step.classList.toggle('active', Number(step.dataset.step) === number));
  progress.forEach((item, index) => {
    item.classList.toggle('active', index + 1 === number);
    item.classList.toggle('done', index + 1 < number);
    item.disabled = index + 1 > number;
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function postJson(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({ error: 'Unerwartete Serverantwort.' }));
  if (!response.ok) throw new Error(data.error || 'Der Vorgang ist fehlgeschlagen.');
  return data;
}

function showTokens(data) {
  if (typeof data.access_token !== 'string' || !data.access_token) {
    throw new Error('Die Anmeldung lieferte keinen Access-Token.');
  }
  document.querySelector('#access-token').value = data.access_token || '';
  document.querySelector('#refresh-token').value = data.refresh_token || '';
  document.querySelector('#expiry').textContent = data.expires_in ? `${data.expires_in} Sekunden` : '';
  const hints = data.jwt_hints || {};
  document.querySelector('#token-meta').replaceChildren(
    ...Object.entries(hints).map(([key, value]) => {
      const item = document.createElement('span');
      item.textContent = `${key}: ${value}`;
      return item;
    }),
  );
  showStep(2);
}

startForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = document.querySelector('#start-error');
  const button = startForm.querySelector('button[type="submit"]');
  error.textContent = '';
  button.disabled = true;
  try {
    const data = await postJson('/api/flow', {
      username: document.querySelector('#username').value,
      password: document.querySelector('#password').value,
      client_id: document.querySelector('#client-id').value,
    });
    showTokens(data);
  } catch (problem) {
    error.textContent = problem.message;
  } finally {
    document.querySelector('#password').value = '';
    button.disabled = false;
  }
});

document.querySelector('#clear').addEventListener('click', () => {
  document.querySelector('#access-token').value = '';
  document.querySelector('#refresh-token').value = '';
  document.querySelector('#password').value = '';
  document.querySelector('#token-meta').replaceChildren();
  showStep(1);
});

document.querySelectorAll('.copy').forEach((button) => {
  button.addEventListener('click', async () => {
    const field = document.querySelector(`#${button.dataset.copy}`);
    await navigator.clipboard.writeText(field.value);
    const oldLabel = button.textContent;
    button.textContent = 'Kopiert';
    window.setTimeout(() => { button.textContent = oldLabel; }, 1300);
  });
});

window.addEventListener('beforeunload', () => {
  document.querySelector('#access-token').value = '';
  document.querySelector('#refresh-token').value = '';
});
