from random import shuffle

class BaseEntity(object):
    def __init__(self, name, attack, life):
        self.life = life
        self.name = name
        self.attack = attack
        self.life = life
        self.alive = True
    
    def battle(self, other):
        self.life -= other.attack
        if self.life <= 0:
            self.life = False
    
        other.life -= self.attack
        if other.life <= 0:
            other.alive = False


class Card(BaseEntity):
    def __init__(self, name, attack, life):
        BaseEntity.__init__(self, name, attack, life)


class Hero(BaseEntity):
    def __init__(self, name, attack, life, deck):
        BaseEntity.__init__(self, name, life, attack)
        self.deck = deck
    
    def heal(self, entity, life=0):
        entity.life += life


class Deck(object):
    def __init__(self):
        self.cards= list()
  
    def add_card(self, card):
        self.cards.append(card)

    def del_card(self, card):
        self.cards.remove(card)

    def shuffle(self):
        shuffle(self.cards)

    def pull(self):
        try:
            return self.cards.pop()
        except IndexError:
            return None


c1 = Card(name="Cartman", attack=2, life=10)
c2 = Card(name="Butters", attack=1, life=20)

print c2.life

c1.battle(c2)

print c2.life