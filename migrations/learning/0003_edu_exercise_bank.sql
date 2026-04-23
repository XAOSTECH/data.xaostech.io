-- =============================================================================
-- Exercise Bank D1 Migration
-- Extends the exercises table from 0001 with additional columns for the exercise bank,
-- then seeds static exercise data.
-- =============================================================================

-- Add columns needed for exercise bank (0001 created exercises with a different schema)
ALTER TABLE exercises ADD COLUMN instruction TEXT NOT NULL DEFAULT '';
ALTER TABLE exercises ADD COLUMN content_json TEXT;
ALTER TABLE exercises ADD COLUMN content_rating TEXT DEFAULT 'E';
ALTER TABLE exercises ADD COLUMN min_age INTEGER DEFAULT 0;
ALTER TABLE exercises ADD COLUMN is_active INTEGER DEFAULT 1;
ALTER TABLE exercises ADD COLUMN tags_json TEXT;
ALTER TABLE exercises ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;

-- Indexes for exercise bank queries
CREATE INDEX IF NOT EXISTS idx_exercises_type ON exercises(type);
CREATE INDEX IF NOT EXISTS idx_exercises_rating ON exercises(content_rating);
CREATE INDEX IF NOT EXISTS idx_exercises_active ON exercises(is_active);
CREATE INDEX IF NOT EXISTS idx_exercises_subject_difficulty ON exercises(subject, difficulty);

-- =============================================================================
-- SEED DATA: Mathematics Exercises
-- =============================================================================

INSERT OR IGNORE INTO exercises (id, subject, category, topic, difficulty, type, instruction, content_json, solution_json, hints_json, tags_json, content_rating)
VALUES
-- Algebra - Beginner
('math-alg-001', 'mathematics', 'algebra', 'algebra', 'beginner', 'multiple-choice',
 'Solve for x in the equation.',
 '{"type":"multiple-choice","question":"If 2x + 4 = 10, what is the value of x?","options":[{"id":"a","text":"x = 2"},{"id":"b","text":"x = 3"},{"id":"c","text":"x = 4"},{"id":"d","text":"x = 5"}],"multiSelect":false}',
 '{"correctAnswer":"b","explanation":"To solve 2x + 4 = 10, subtract 4 from both sides to get 2x = 6, then divide by 2 to get x = 3.","steps":[{"stepNumber":1,"description":"Start with 2x + 4 = 10"},{"stepNumber":2,"description":"Subtract 4 from both sides: 2x = 6"},{"stepNumber":3,"description":"Divide both sides by 2: x = 3"}]}',
 '["Try isolating the variable on one side","First remove the constant term"]',
 '["algebra","linear-equations","solving-for-x"]',
 'E'),

-- Algebra - Intermediate (Quadratic)
('math-alg-002', 'mathematics', 'algebra', 'algebra', 'intermediate', 'calculation',
 'Solve the quadratic equation.',
 '{"type":"calculation","problem":"Find the roots of x² - 5x + 6 = 0","units":"none"}',
 '{"correctAnswer":"x = 2 or x = 3","explanation":"Factor the quadratic: (x - 2)(x - 3) = 0. Setting each factor to zero gives x = 2 or x = 3.","steps":[{"stepNumber":1,"description":"Identify the quadratic: x² - 5x + 6 = 0"},{"stepNumber":2,"description":"Find factors of 6 that add to -5: (-2) and (-3)"},{"stepNumber":3,"description":"Factor: (x - 2)(x - 3) = 0"},{"stepNumber":4,"description":"Solve: x = 2 or x = 3"}]}',
 '["Try factoring the quadratic","Look for two numbers that multiply to 6 and add to -5"]',
 '["algebra","quadratic-equations","factoring"]',
 'E'),

-- Geometry - Beginner
('math-geo-001', 'mathematics', 'geometry', 'geometry', 'beginner', 'multiple-choice',
 'Calculate the area of the shape.',
 '{"type":"multiple-choice","question":"What is the area of a rectangle with length 8 cm and width 5 cm?","options":[{"id":"a","text":"13 cm²"},{"id":"b","text":"26 cm²"},{"id":"c","text":"40 cm²"},{"id":"d","text":"80 cm²"}],"multiSelect":false}',
 '{"correctAnswer":"c","explanation":"Area of a rectangle = length × width = 8 × 5 = 40 cm²"}',
 '["Area formula for rectangle: length × width","Multiply the two dimensions"]',
 '["geometry","area","rectangles"]',
 'E'),

-- Fractions - Beginner
('math-frac-001', 'mathematics', 'arithmetic', 'fractions', 'beginner', 'fill-blank',
 'Complete the fraction operation.',
 '{"type":"fill-blank","template":"1/2 + 1/4 = [BLANK]","blankCount":1,"wordBank":["3/4","2/6","1/6","3/8"]}',
 '{"correctAnswer":"3/4","explanation":"To add fractions, find a common denominator. 1/2 = 2/4, so 2/4 + 1/4 = 3/4"}',
 '["Find a common denominator","Convert 1/2 to fourths"]',
 '["fractions","addition","common-denominator"]',
 'E');

-- =============================================================================
-- SEED DATA: Science Exercises
-- =============================================================================

INSERT OR IGNORE INTO exercises (id, subject, category, topic, difficulty, type, instruction, content_json, solution_json, hints_json, tags_json, content_rating)
VALUES
-- Biology - Beginner
('sci-bio-001', 'science', 'biology', 'biology', 'beginner', 'multiple-choice',
 'Answer the biology question.',
 '{"type":"multiple-choice","question":"What is the powerhouse of the cell?","options":[{"id":"a","text":"Nucleus"},{"id":"b","text":"Mitochondria"},{"id":"c","text":"Ribosome"},{"id":"d","text":"Cell membrane"}],"multiSelect":false}',
 '{"correctAnswer":"b","explanation":"Mitochondria are often called the \"powerhouse of the cell\" because they produce ATP (adenosine triphosphate), the main energy currency of cells."}',
 '["It produces energy for the cell","Think about cellular respiration"]',
 '["biology","cells","organelles"]',
 'E'),

-- Chemistry - Intermediate
('sci-chem-001', 'science', 'chemistry', 'chemistry', 'intermediate', 'multiple-choice',
 'Identify the element.',
 '{"type":"multiple-choice","question":"Which element has the atomic number 6?","options":[{"id":"a","text":"Hydrogen"},{"id":"b","text":"Helium"},{"id":"c","text":"Carbon"},{"id":"d","text":"Nitrogen"}],"multiSelect":false}',
 '{"correctAnswer":"c","explanation":"Carbon has 6 protons in its nucleus, giving it an atomic number of 6. It is essential for all known life forms."}',
 '["Atomic number = number of protons","This element is the basis of organic chemistry"]',
 '["chemistry","periodic-table","elements"]',
 'E'),

-- Physics - Intermediate
('sci-phys-001', 'science', 'physics', 'physics', 'intermediate', 'calculation',
 'Calculate the physical quantity.',
 '{"type":"calculation","problem":"A car travels 120 km in 2 hours. What is its average speed?","units":"km/h"}',
 '{"correctAnswer":"60 km/h","explanation":"Speed = Distance / Time = 120 km / 2 hours = 60 km/h","steps":[{"stepNumber":1,"description":"Identify: Distance = 120 km, Time = 2 hours"},{"stepNumber":2,"description":"Apply formula: Speed = Distance / Time"},{"stepNumber":3,"description":"Calculate: 120 / 2 = 60 km/h"}]}',
 '["Use the formula: Speed = Distance / Time","Make sure units are consistent"]',
 '["physics","motion","speed"]',
 'E');

-- =============================================================================
-- SEED DATA: History Exercises
-- =============================================================================

INSERT OR IGNORE INTO exercises (id, subject, category, topic, difficulty, type, instruction, content_json, solution_json, hints_json, tags_json, content_rating)
VALUES
-- American History - Beginner
('hist-us-001', 'history', 'american-history', 'american-history', 'beginner', 'multiple-choice',
 'Answer the history question.',
 '{"type":"multiple-choice","question":"In what year did the United States declare independence?","options":[{"id":"a","text":"1774"},{"id":"b","text":"1776"},{"id":"c","text":"1778"},{"id":"d","text":"1781"}],"multiSelect":false}',
 '{"correctAnswer":"b","explanation":"The United States declared independence on July 4, 1776, when the Continental Congress adopted the Declaration of Independence."}',
 '["Think about the famous date Americans celebrate","July 4th is a big hint"]',
 '["history","american-revolution","independence"]',
 'E'),

-- World History - Intermediate
('hist-world-001', 'history', 'world-history', 'world-history', 'intermediate', 'multiple-choice',
 'Identify the historical event.',
 '{"type":"multiple-choice","question":"The fall of the Berlin Wall occurred in which year?","options":[{"id":"a","text":"1987"},{"id":"b","text":"1989"},{"id":"c","text":"1991"},{"id":"d","text":"1993"}],"multiSelect":false}',
 '{"correctAnswer":"b","explanation":"The Berlin Wall fell on November 9, 1989, marking a pivotal moment in the end of the Cold War and leading to German reunification in 1990."}',
 '["It was near the end of the Cold War","Germany was reunified shortly after"]',
 '["history","cold-war","germany","20th-century"]',
 'E');

-- =============================================================================
-- SEED DATA: Language/English Exercises
-- =============================================================================

INSERT OR IGNORE INTO exercises (id, subject, category, topic, difficulty, type, instruction, content_json, solution_json, hints_json, tags_json, content_rating)
VALUES
-- Grammar - Beginner
('lang-gram-001', 'language', 'grammar', 'grammar', 'beginner', 'fill-blank',
 'Choose the correct word to complete the sentence.',
 '{"type":"fill-blank","template":"She [BLANK] to the store yesterday.","blankCount":1,"wordBank":["go","goes","went","going"]}',
 '{"correctAnswer":"went","explanation":"\"Went\" is the past tense of \"go\". Since the sentence uses \"yesterday\", we need past tense."}',
 '["Look at the time indicator \"yesterday\"","Past tense is needed"]',
 '["grammar","verb-tenses","past-tense"]',
 'E'),

-- Vocabulary - Intermediate
('lang-vocab-001', 'language', 'vocabulary', 'vocabulary', 'intermediate', 'multiple-choice',
 'Select the word that best matches the definition.',
 '{"type":"multiple-choice","question":"Which word means \"to make something seem less important than it really is\"?","options":[{"id":"a","text":"Exaggerate"},{"id":"b","text":"Understate"},{"id":"c","text":"Elaborate"},{"id":"d","text":"Emphasize"}],"multiSelect":false}',
 '{"correctAnswer":"b","explanation":"To understate means to present something as being smaller, worse, or less important than it actually is. It is the opposite of exaggerate."}',
 '["Think about the prefix \"under-\"","The opposite would be making things seem bigger"]',
 '["vocabulary","word-meanings","communication"]',
 'E');

-- =============================================================================
-- SEED DATA: Computer Science Exercises
-- =============================================================================

INSERT OR IGNORE INTO exercises (id, subject, category, topic, difficulty, type, instruction, content_json, solution_json, hints_json, tags_json, content_rating)
VALUES
-- Programming Basics - Beginner
('cs-prog-001', 'computer-science', 'programming', 'programming', 'beginner', 'multiple-choice',
 'Answer the programming question.',
 '{"type":"multiple-choice","question":"What does HTML stand for?","options":[{"id":"a","text":"Hyper Text Markup Language"},{"id":"b","text":"High Tech Modern Language"},{"id":"c","text":"Hyper Transfer Markup Language"},{"id":"d","text":"Home Tool Markup Language"}],"multiSelect":false}',
 '{"correctAnswer":"a","explanation":"HTML stands for Hyper Text Markup Language. It is the standard markup language used to create and structure content on web pages."}',
 '["It is used for web pages","\"Markup\" is a key word"]',
 '["programming","web-development","html"]',
 'E'),

-- Algorithms - Intermediate
('cs-algo-001', 'computer-science', 'algorithms', 'algorithms', 'intermediate', 'multiple-choice',
 'Analyze the algorithm complexity.',
 '{"type":"multiple-choice","question":"What is the time complexity of binary search?","options":[{"id":"a","text":"O(n)"},{"id":"b","text":"O(n²)"},{"id":"c","text":"O(log n)"},{"id":"d","text":"O(1)"}],"multiSelect":false}',
 '{"correctAnswer":"c","explanation":"Binary search has O(log n) time complexity because it divides the search space in half with each comparison, requiring at most log₂(n) comparisons."}',
 '["It divides the search space in half each time","Think logarithmically"]',
 '["algorithms","binary-search","complexity","big-o"]',
 'E10');
