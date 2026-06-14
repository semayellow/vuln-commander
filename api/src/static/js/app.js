(function () {
  const PRIMARY = '#FF8400';
  const SIZE = 42;
  const GAP = 2;
  const ROWS = 7;
  const COLS = 7;
  const MAX_OPACITY = 0.32;
  const FADE_STEP = 0.08;

  function onReady(callback) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', callback);
      return;
    }
    callback();
  }

  function hexPoints(size) {
    const cx = size / 2;
    const cy = size / 2;
    const r = size * 0.46;
    const points = [];
    for (let i = 0; i < 6; i += 1) {
      const angle = (Math.PI / 3) * i - Math.PI / 6;
      points.push(`${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`);
    }
    return points.join(' ');
  }

  function renderHoneycomb(container) {
    const dx = SIZE * 0.78 + GAP;
    const dy = SIZE * 0.67 + GAP;
    const clusterW = (COLS - 1) * dx + SIZE;
    const clusterH = (ROWS - 1) * dy + SIZE;

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', String(clusterW));
    svg.setAttribute('height', String(clusterH));
    svg.setAttribute('viewBox', `0 0 ${clusterW} ${clusterH}`);
    svg.setAttribute('aria-hidden', 'true');

    for (let row = 0; row < ROWS; row += 1) {
      for (let col = 0; col < COLS; col += 1) {
        const offsetX = row % 2 === 1 ? dx / 2 : 0;
        const dist = (COLS - 1 - col) + (ROWS - 1 - row);
        const opacity = Math.max(0, MAX_OPACITY - dist * FADE_STEP);
        if (opacity <= 0.01) {
          continue;
        }

        const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        polygon.setAttribute('points', hexPoints(SIZE));
        polygon.setAttribute('fill', PRIMARY);
        polygon.setAttribute('opacity', String(opacity));
        polygon.setAttribute('transform', `translate(${col * dx + offsetX}, ${row * dy})`);
        svg.appendChild(polygon);
      }
    }

    container.appendChild(svg);
  }

  function pluralize(count, entityName) {
    return count === 1 ? entityName : `${entityName}s`;
  }

  function getDataRows(table) {
    return Array.from(table.querySelectorAll('tbody tr')).filter(
      (row) => !row.querySelector('.table-empty'),
    );
  }

  function getVisiblePages(currentPage, totalPages, maxVisible = 5) {
    if (totalPages <= maxVisible) {
      return Array.from({ length: totalPages }, (_, index) => index + 1);
    }

    let start = currentPage - Math.floor(maxVisible / 2);
    let end = start + maxVisible - 1;

    if (start < 1) {
      start = 1;
      end = maxVisible;
    }

    if (end > totalPages) {
      end = totalPages;
      start = totalPages - maxVisible + 1;
    }

    return Array.from({ length: end - start + 1 }, (_, index) => start + index);
  }

  function renderPagination(nav, currentPage, totalPages) {
    nav.innerHTML = '';

    const prev = document.createElement('button');
    prev.type = 'button';
    prev.className = 'pagination__button';
    prev.textContent = 'Previous';
    prev.dataset.page = 'prev';
    prev.disabled = currentPage <= 1;
    nav.appendChild(prev);

    getVisiblePages(currentPage, totalPages).forEach((page) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'pagination__button pagination__button--page';
      if (page === currentPage) {
        button.classList.add('pagination__button--active');
      }
      button.textContent = String(page);
      button.dataset.page = String(page);
      nav.appendChild(button);
    });

    const next = document.createElement('button');
    next.type = 'button';
    next.className = 'pagination__button';
    next.textContent = 'Next';
    next.dataset.page = 'next';
    next.disabled = currentPage >= totalPages;
    nav.appendChild(next);
  }

  function initTableControls() {
    const tableControllers = new Map();
    window.__vcTableControllers = tableControllers;

    document.querySelectorAll('select[data-page-size]').forEach((select) => {
      const tableId = select.getAttribute('data-page-size');
      if (!tableId) {
        return;
      }

      const table = document.getElementById(tableId);
      const panel = table?.closest('.data-panel');
      const summary = panel?.querySelector(`[data-table-summary="${tableId}"]`);
      const paginationNav = panel?.querySelector(`[data-table-pagination="${tableId}"]`);
      const searchInput = panel?.querySelector(`[data-table-search="${tableId}"]`);
      const entityName = summary?.dataset.entityName ?? 'record';

      if (!table || !paginationNav) {
        return;
      }

      let currentPage = 1;
      let pageSize = Number.parseInt(select.value, 10) || 25;

      function getMatchingRows() {
        const query = searchInput?.value.trim().toLowerCase() ?? '';
        return getDataRows(table).filter((row) => {
          if (query === '') {
            return true;
          }
          return (row.textContent?.toLowerCase() ?? '').includes(query);
        });
      }

      function apply() {
        const rows = getMatchingRows();
        const total = rows.length;
        const totalPages = Math.max(1, Math.ceil(total / pageSize));
        currentPage = Math.min(Math.max(currentPage, 1), totalPages);

        const start = (currentPage - 1) * pageSize;
        const end = start + pageSize;

        getDataRows(table).forEach((row) => {
          row.hidden = true;
        });

        rows.forEach((row, index) => {
          row.hidden = index < start || index >= end;
        });

        const emptyRow = table.querySelector('tbody .table-empty')?.closest('tr');
        if (emptyRow) {
          emptyRow.hidden = total > 0;
        }

        if (summary) {
          summary.textContent = `Showing ${total} ${pluralize(total, entityName)}`;
        }

        renderPagination(paginationNav, currentPage, totalPages);
      }

      select.addEventListener('change', () => {
        pageSize = Number.parseInt(select.value, 10) || 25;
        currentPage = 1;
        apply();
      });

      searchInput?.addEventListener('input', () => {
        currentPage = 1;
        apply();
      });

      paginationNav.addEventListener('click', (event) => {
        const button = event.target.closest('[data-page]');
        if (!button || button.disabled) {
          return;
        }

        if (button.dataset.page === 'prev') {
          currentPage -= 1;
        } else if (button.dataset.page === 'next') {
          currentPage += 1;
        } else {
          currentPage = Number.parseInt(button.dataset.page, 10);
        }

        apply();
      });

      tableControllers.set(tableId, {
        apply,
        resetPage() {
          currentPage = 1;
          apply();
        },
      });

      apply();
    });
  }

  window.vcRefreshTable = function (tableId, { resetPage = false } = {}) {
    const controller = window.__vcTableControllers?.get(tableId);
    if (!controller) {
      return;
    }
    if (resetPage) {
      controller.resetPage();
      return;
    }
    controller.apply();
  };

  onReady(() => {
    document.querySelectorAll('.honeycomb-layer').forEach(renderHoneycomb);
  });

  initTableControls();
})();
