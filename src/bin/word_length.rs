fn find_longest(word_array: &Vec<String>) -> &str {
    if word_array.is_empty() {
        return "";
    }

    let mut word_lengths : Vec<usize> = vec![];

    for word in word_array {
        word_lengths.push(word.len());
    }

    let longest_word_index : usize = find_max_in_vector(word_lengths);

    return &word_array[longest_word_index]
}

fn find_max_in_vector(vector: Vec<usize>) -> usize {
    let mut current_longest = 0;

    for i in 0..vector.len() {
        if vector[i] > vector[current_longest] {
            current_longest = i;
        }
    }

    return current_longest
}

fn main() {
    let words = vec![
        String::from("rust"),
        String::from("programming"),
        String::from("fun")
    ];
    
    let longest = find_longest(&words);
    println!("Longest word: {}", longest);  // should print "programming"
    println!("Original vector still works: {:?}", words);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_longest() {
        let words = vec![
            String::from("Colorado"),
            String::from("Utah"),
            String::from("Mississippi"),
        ];
        assert_eq!(find_longest(&words), "Mississippi");
    }

    #[test]
    fn test_empty_vector() {
        let words = vec![];
        assert_eq!(find_longest(&words), "");
    }

    #[test]
    fn test_equivalent_length_words() {
        let words = vec![
            String::from("Green"),
            String::from("Brown"),
            String::from("Red")
        ];
        assert_eq!(find_longest(&words), "Green")
    }
}