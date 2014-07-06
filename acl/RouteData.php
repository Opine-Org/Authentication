<?php return array (
  0 => 
  array (
    '/Manager' => 
    array (
      'GET' => 
      array (
        0 => 'AuthData',
        1 => 'auth53b925f061bb2',
      ),
    ),
    '/Manager/add/Users/users' => 
    array (
      'GET' => 
      array (
        0 => 'AuthData',
        1 => 'auth53b925f061c37',
      ),
    ),
    '/Manager/list/Users' => 
    array (
      'GET' => 
      array (
        0 => 'AuthData',
        1 => 'auth53b925f061d6a',
      ),
    ),
  ),
  1 => 
  array (
    0 => 
    array (
      'regex' => '~^(?|/Manager/edit/Users/users\\:([^/]+))$~',
      'routeMap' => 
      array (
        2 => 
        array (
          'GET' => 
          array (
            0 => 
            array (
              0 => 'AuthData',
              1 => 'auth53b925f061c49',
            ),
            1 => 
            array (
              'id' => 'id',
            ),
          ),
        ),
      ),
    ),
  ),
);