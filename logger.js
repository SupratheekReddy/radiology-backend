const winston = require('winston');
const { LogstashTransport } = require('winston-logstash-transport');

class LogstashTransportWithFix extends LogstashTransport {
  transform(info) {
    // Add newline so Logstash json_lines codec reads it
    const message = JSON.stringify(info) + '\n';
    return Buffer.from(message);
  }
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),

  transports: [
    new winston.transports.Console(),

    new LogstashTransportWithFix({
      host: '127.0.0.1',
      port: 5044,
      protocol: 'tcp'
    })
  ]
});

module.exports = logger;
