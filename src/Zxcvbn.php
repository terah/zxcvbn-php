<?php

namespace ZxcvbnPhp;

class Zxcvbn
{
    /**
     * @var
     */
    protected $scorer;

    /**
     * @var
     */
    protected $searcher;

    /**
     * @var
     */
    protected $matcher;

    /**
     * @var array
     */
    protected $params;

    public function __construct(array $params=array())
    {
        $this->scorer = new Scorer();
        $this->searcher = new Searcher();
        $this->matcher = new Matcher();
        $this->params  = $params;
    }

    /**
     * Calculate password strength via non-overlapping minimum entropy patterns.
     *
     * @param string $password   Password to measure
     * @param array  $userInputs Optional user inputs
     *
     * @return array Strength result array with keys:
     *               password
     *               entropy
     *               match_sequence
     *               score
     */
    public function passwordStrength($password, array $userInputs = [])
    {
        $timeStart = microtime(true);
        if ('' === $password) {
            $timeStop = microtime(true) - $timeStart;

            return $this->result($password, 0, [], 0, ['calc_time' => $timeStop]);
        }

        // Get matches for $password.
        $matches = $this->matcher->getMatches($password, $userInputs, $this->params);

        // Calcuate minimum entropy and get best match sequence.
        $entropy = $this->searcher->getMinimumEntropy($password, $matches);
        $bestMatches = $this->searcher->matchSequence;

        // Calculate score and get crack time.
        $score = $this->scorer->score($entropy);
        $metrics = $this->scorer->getMetrics();

        $timeStop = microtime(true) - $timeStart;
        // Include metrics and calculation time.
        $params = array_merge($metrics, ['calc_time' => $timeStop]);

        return $this->result($password, $entropy, $bestMatches, $score, $params);
    }

    /**
     * @param string[] $words
     * @param string $type
     * @return bool
     */
    public function addWordsToPasswordList(array $words, $type)
    {
        $fileName       = ! empty($this->params['dictionary_file']) ? $this->params['dictionary_file'] : dirname(__FILE__) . '/Matchers/ranked_frequency_lists.json';
        $data           = file_get_contents($fileName);
        $data           = json_decode($data, true);
        $data[$type]    = array_key_exists($type, $data) ? $data[$type] : [];
        $changed        = false;
        foreach ( $words as $word )
        {
            $word = preg_replace("/[^0-9a-z']/", '', strtolower(trim($word)));
            if ( is_numeric($word) || empty($word) || strlen($word) < 4 )
            {
                continue;
            }
            if ( static::isInPasswordLists($word, $data) )
            {
                continue;
            }
            $nextVal            = empty($data[$type]) ? 1 : max($data[$type]) + 1;
            $data[$type][$word] = $nextVal;
            $changed            = true;
        }
        if ( ! $changed )
        {
            return true;
        }
        $data           = json_encode($data);
        if ( ! $data || ! file_put_contents($fileName, $data) )
        {
            return false;
        }
        return true;
    }

    /**
     * @param string $word
     * @param array $lists
     * @return bool
     */
    protected static function isInPasswordLists($word, array $lists)
    {
        foreach ( $lists as $category => $list )
        {
            if ( array_key_exists($word, $list) )
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Result array.
     *
     * @param string $password
     * @param float  $entropy
     * @param array  $matches
     * @param int    $score
     * @param array  $params
     *
     * @return array
     */
    protected function result($password, $entropy, $matches, $score, $params = [])
    {
        $r = [
            'password' => $password,
            'entropy' => $entropy,
            'match_sequence' => $matches,
            'score' => $score,
        ];

        return array_merge($params, $r);
    }
}
