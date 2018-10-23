func (user *User) rename(name string) {
  name = name  // Noncompliant
}

func printTen() {
	myNumber := 010 // Noncompliant. myNumber will hold 8, not 10 - was this really expected?
	fmt.Println(myNumber)
}
