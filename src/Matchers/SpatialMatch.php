<?php

namespace ZxcvbnPhp\Matchers;

/**
 * Class SpatialMatch.
 */
class SpatialMatch extends Match
{
    /**
     * @var
     */
    public $shiftedCount;

    /**
     * @var
     */
    public $turns;

    /**
     * @var
     */
    public $graph;

    /**
     * @var
     */
    protected $keyboardStartingPos;

    /**
     * @var
     */
    protected $keypadStartingPos;

    /**
     * @var
     */
    protected $keyboardAvgDegree;

    /**
     * @var
     */
    protected $keypadAvgDegree;

    /**
     * @param $password
     * @param $begin
     * @param $end
     * @param $token
     * @param array $params
     */
    public function __construct($password, $begin, $end, $token, $params = [])
    {
        parent::__construct($password, $begin, $end, $token);
        $this->pattern = 'spatial';
        $this->graph = $params['graph'];
        if (!empty($params)) {
            $this->shiftedCount = isset($params['shifted_count']) ? $params['shifted_count'] : null;
            $this->turns = isset($params['turns']) ? $params['turns'] : null;
        }
        // Preset properties since adjacency graph is constant for qwerty keyboard and keypad.
        $this->keyboardStartingPos = 94;
        $this->keypadStartingPos = 15;
        $this->keyboardAvgDegree = 432 / 94;
        $this->keypadAvgDegree = 76 / 15;
    }

    /**
     * Match spatial patterns based on keyboard layouts (e.g. qwerty, dvorak, keypad).
     *
     * @copydoc Match::match()
     *
     * @param       $password
     * @param array $userInputs
     *
     * @return array
     */
    public static function match($password, array $userInputs = [], array $params = [])
    {
        $matches = [];
        $graphs = static::getAdjacencyGraphs();
        foreach ($graphs as $name => $graph) {
            $results = static::graphMatch($password, $graph);
            foreach ($results as $result) {
                $result['graph'] = $name;
                $matches[] = new static($password, $result['begin'], $result['end'], $result['token'], $result);
            }
        }

        return $matches;
    }

    /**
     * Get entropy.
     *
     * @return float
     */
    public function getEntropy()
    {
        if ('qwerty' === $this->graph || 'dvorak' === $this->graph) {
            $startingPos = $this->keyboardStartingPos;
            $avgDegree = $this->keyboardAvgDegree;
        } else {
            $startingPos = $this->keypadStartingPos;
            $avgDegree = $this->keypadAvgDegree;
        }

        $possibilities = 0;
        // estimate the number of possible patterns w/ token length or less with match turns or less.
        $tokenLength = strlen($this->token);
        for ($i = 2; $i <= $tokenLength; ++$i) {
            $possibleTurns = min($this->turns, $i - 1);

            for ($j = 1; $j <= $possibleTurns; ++$j) {
                $possibilities += $this->binom($i - 1, $j - 1) * $startingPos * ($avgDegree ** $j);
            }
        }
        $entropy = $this->log($possibilities);

        // add extra entropy for shifted keys. (% instead of 5, A instead of a.)
        if (!empty($this->shiftedCount)) {
            $possibilities = 0;
            $unshiftedCount = strlen($this->token) - $this->shiftedCount;
            $len = min($this->shiftedCount, $unshiftedCount);

            for ($i = 0; $i <= $len; ++$i) {
                $possibilities += $this->binom($this->shiftedCount + $unshiftedCount, $i);
            }
            $entropy += $this->log($possibilities);
        }

        return $entropy;
    }

    /**
     * @param bool $obfuscate
     * @return string
     */
    public function getMatch($obfuscate=false)
    {
        $match      = $obfuscate ? $this->obfuscateWord($this->token) : $this->token;

        return "The password contains common keyboard patterns: {$match}.";
    }

    /**
     * Match spatial patterns in a adjacency graph.
     *
     * @param string $password
     * @param array  $graph
     *
     * @return array
     */
    protected static function graphMatch($password, $graph)
    {
        $result = [];
        $i = 0;

        $passwordLength = strlen($password);

        while ($i < $passwordLength - 1) {
            $j = $i + 1;
            $lastDirection = null;
            $turns = 0;
            $shiftedCount = 0;

            while (true) {
                $prevChar = $password[$j - 1];
                $found = false;
                $curDirection = -1;
                $adjacents = isset($graph[$prevChar]) ? $graph[$prevChar] : [];
                // Consider growing pattern by one character if j hasn't gone over the edge.
                if ($j < $passwordLength) {
                    $curChar = $password[$j];
                    foreach ($adjacents as $adj) {
                        ++$curDirection;
                        $curCharPos = static::indexOf($adj, $curChar);
                        if ($adj && $curCharPos !== -1) {
                            $found = true;
                            $foundDirection = $curDirection;

                            if (1 === $curCharPos) {
                                // index 1 in the adjacency means the key is shifted, 0 means unshifted: A vs a, % vs 5, etc.
                                // for example, 'q' is adjacent to the entry '2@'. @ is shifted w/ index 1, 2 is unshifted.
                                ++$shiftedCount;
                            }
                            if ($lastDirection !== $foundDirection) {
                                // adding a turn is correct even in the initial case when last_direction is null:
                                // every spatial pattern starts with a turn.
                                ++$turns;
                                $lastDirection = $foundDirection;
                            }

                            break;
                        }
                    }
                }

                // if the current pattern continued, extend j and try to grow again
                if ($found) {
                    ++$j;
                }
                // otherwise push the pattern discovered so far, if any...
                else {
                    // Ignore length 1 or 2 chains.
                    if ($j - $i > 2) {
                        $result[] = [
                            'begin' => $i,
                            'end' => $j - 1,
                            'token' => substr($password, $i, $j - $i),
                            'turns' => $turns,
                            'shifted_count' => $shiftedCount,
                        ];
                    }
                    // ...and then start a new search for the rest of the password.
                    $i = $j;

                    break;
                }
            }
        }

        return $result;
    }

    /**
     * Get the index of a string a character first.
     *
     * @param string $string
     * @param string $char
     *
     * @return int
     */
    protected static function indexOf($string, $char)
    {
        $pos = @strpos($string, $char);

        return false === $pos ? -1 : $pos;
    }

    /**
     * Calculate the average degree for all keys in a adjancency graph.
     *
     * @param array $graph
     *
     * @return float
     */
    protected static function calcAverageDegree($graph)
    {
        $sum = 0;
        foreach ($graph as $neighbors) {
            foreach ($neighbors as $neighbor) {
                // Ignore empty neighbors.
                if (null !== $neighbor) {
                    ++$sum;
                }
            }
        }

        return $sum / count(array_keys($graph));
    }

    /**
     * Load adjacency graphs.
     *
     * @return array
     */
    protected static function getAdjacencyGraphs()
    {
        $data = file_get_contents(__DIR__.'/adjacency_graphs.json');

        return json_decode($data, true);
    }
}
