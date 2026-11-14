// Tiny event dispatcher so pages need no inline onclick/onchange attributes (required for a strict CSP).
// Markup:   <button data-click="openAddModal">   <input type="radio" data-change="switchTab">
// Register: Object.assign(Actions, { openAddModal: () => openAddModal() });
const Actions = {};

function dispatch(type, attr) {
    document.addEventListener(type, (e) => {
        const el = e.target.closest('[' + attr + ']');
        if (!el) return;
        const fn = Actions[el.getAttribute(attr)];
        if (fn) fn(el, e);
    });
}
dispatch('click', 'data-click');
dispatch('change', 'data-change');

Actions.logout = () => API.logout().then(() => { window.location.href = '/static/pages/login.html'; });
