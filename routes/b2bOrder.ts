/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function isSafeInput (input: string): boolean {
  // Disallow characters that can be used for string construction, escaping, private fields, or property access:
  // - Quotes: ", ', `
  // - Backslash: \
  // - Brackets: [, ]
  // - Dot: .
  // - Forward slash: /
  // - Hash: #
  const forbiddenChars = ['"', "'", '`', '\\', '[', ']', '.', '/', '#']
  for (const char of forbiddenChars) {
    if (input.includes(char)) {
      return false
    }
  }

  // Blocklist of dangerous keywords/constructs with word boundaries
  const dangerousPatterns = [
    /\bconstructor\b/i,
    /\bprototype\b/i,
    /\b__proto__\b/i,
    /\bprocess\b/i,
    /\brequire\b/i,
    /\bglobal\b/i,
    /\bglobalThis\b/i,
    /\bmodule\b/i,
    /\bBuffer\b/i,
    /\bmainModule\b/i,
    /\bexports\b/i,
    /\bReflect\b/i,
    /\bProxy\b/i,
    /\bFunction\b/, // Case-sensitive to allow lowercase "function" keyword
    /\beval\b/i,
    /\bexec\b/i,
    /\bexecSync\b/i,
    /\bspawn\b/i,
    /\bfork\b/i,
    /\bthis\b/i
  ]

  for (const pattern of dangerousPatterns) {
    if (pattern.test(input)) {
      return false
    }
  }

  return true
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        if (!isSafeInput(orderLinesData)) {
          throw new Error('Blocked dangerous input')
        }
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
