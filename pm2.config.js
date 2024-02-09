// this means if app restart {MAX_RESTART} times in 1 min then it stops
const NODE_ENV = process.env.NODE_ENV || 'development';

const MAX_RESTART = 0;
const MIN_UPTIME = 60000;


module.exports = {
  apps : [
    {
      name   : "snapshotter-lite",
      script : `poetry run python -m snapshotter.system_event_detector`,
      max_restarts: MAX_RESTART,
      min_uptime: MIN_UPTIME,
      error_file: "/dev/null",
      out_file: "/dev/null",
      env: {
        NODE_ENV: NODE_ENV,
      },
      "autorestart" : false
    },

  ]
}
