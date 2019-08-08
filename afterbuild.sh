#!/bin/bash

if (( "$TRAVIS_PULL_REQUEST" != "false" ))
  then
    if ["$TRAVIS_TEST_RESULT" == 0 ]
      then
        COMMENT="Travis build passed: $TRAVIS_BUILD_WEB_URL"
      else
        COMMENT="Travis build failed: $TRAVIS_BUILD_WEB_URL"
     fi
   curl -H "Authorization: token $TOKTOK" -X POST -d "{\"body\": \"$COMMENT\"}" "https://api.github.com/repos/${TRAVIS_REPO_SLUG}/issues/${TRAVIS_PULL_REQUEST}/comments"
fi
