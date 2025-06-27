const barCtx = document.getElementById('barChart').getContext('2d');
new Chart(barCtx, {
  type: 'bar',
  data: {
    labels: ['0h', '1h', '2h', '3h', '4h', '5h'],
    datasets: [{
      label: 'Incidents',
      data: [1, 2, 3, 2, 1, 4],
      backgroundColor: '#0d6efd'
    }]
  },
  options: {
    responsive: true,
    animation: false
  }
});

const pieCtx = document.getElementById('pieChart').getContext('2d');
new Chart(pieCtx, {
  type: 'pie',
  data: {
    labels: ['Critique', 'HTTP', 'FTP', 'SSH', 'TELNET'],
    datasets: [{
      data: [30, 20, 15, 25, 10],
      backgroundColor: ['#dc3545', '#0d6efd', '#20c997', '#ffc107', '#6c757d']
    }]
  },
  options: {
    responsive: true,
    animation: false,
    plugins: {
      legend: {
        position: 'bottom'
      }
    }
  }
});
